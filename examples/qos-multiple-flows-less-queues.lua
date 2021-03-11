--- This script implements a QoS Test with multiple flows with adjustable rates
local mg		= require "moongen"
local memory	= require "memory"
local device	= require "device"
local ts		= require "timestamping"
local filter	= require "filter"
local stats		= require "stats"
local hist		= require "histogram"
local timer		= require "timer"
local arp    	= require "proto.arp"
local log		= require "log"

local PKT_SIZE	= 124 -- without CRC
local DST_MAC		= nil -- resolved via ARP on GW_IP or DST_IP, can be overriden with a string here
local SRC_IP	  	= "10.0.0.10"
local DST_IP		= "10.0.250.10"
local SRC_PORT		= 1234
local DST_PORT_BASE	= 1000

-- answer ARP requests for this IP on the rx port
-- change this if benchmarking something like a NAT device
local RX_IP		= DST_IP
-- used to resolve DST_MAC
local GW_IP		= "10.0.0.1"
-- used as source IP to resolve GW_IP to DST_MAC
local ARP_IP	= SRC_IP

function configure(parser)
	parser:description("Generates two flows of traffic and compares them. This example requires an ixgbe NIC due to the used hardware features.")
	parser:argument("txDev", "Device to transmit from."):convert(tonumber)
	parser:argument("rxDev", "Device to receive from."):convert(tonumber)
	parser:option("-r --rate", "Transmit rate in Mbit/s."):args("*"):default(10000):convert(tonumber)
	parser:option("-b --burst", "Burst in bytes"):args("*"):default(10000):convert(tonumber)
	parser:option("-f --flows", "Number of flows (randomized dest Port)."):default(4):convert(tonumber)
	parser:option("-w --warmup", "Warmup-phase in seconds"):default(0):convert(tonumber)
end

local function tableOfPorts(flows, rate)
    local ports = {}
	for i=1,flows do
		local temp_port = DST_PORT_BASE + i
		for x = 1, rate[i] do
			table.insert(ports, temp_port)
		end
	end
	ports = shuffle(ports)
	return ports
end

-- Source: https://stackoverflow.com/questions/8695378/how-to-sum-a-table-of-numbers-in-lua
function sum(t)
    local sum = 0
    for k,v in pairs(t) do
        sum = sum + v
    end

    return sum
end


function master(args)
	if args.flows ~= (table.getn(args.rate) or table.getn(args.burst)) then
		log:error("Rate and burst are not matching the numbers of flows")
		return -1 -- Error as we have no result here, we need one definition per flow
	end
	local txDev, rxDev
	txDev = device.config{port = args.txDev, rxQueues = 2, txQueues = 3 }
	rxDev = device.config{port = args.rxDev, rxQueues = 2, txQueues = 2 }
	-- wait until the links are up
	device.waitForLinks()
	for i=1,args.flows,1
	do
		log:info("Sending Flow %d with %d MBit/s traffic and Burst %d to UDP port %d", i, args.rate[i], args.burst[i], DST_PORT_BASE + i)
	end
	txDev:getTxQueue(0):setRate(sum(args.rate))
    local ports = tableOfPorts(args.flows, args.rate)
	-- Starting the Tasks for the Queues
	mg.startTask("loadSlave", txDev:getTxQueue(0), ports, args.burst[i])
	-- count the incoming packets
	mg.startTask("counterSlave", rxDev:getRxQueue(0))
	-- measure latency from a second queue
	mg.startSharedTask("timerSlave", txDev:getTxQueue(1), rxDev:getRxQueue(1), args.flows, args.rate, args.warmup)
	arp.startArpTask{
		-- run ARP on both ports
		{ rxQueue = rxDev:getRxQueue(1), txQueue = rxDev:getTxQueue(1), ips = RX_IP },
		-- we need an IP address to do ARP requests on this interface
		{ rxQueue = txDev:getRxQueue(0), txQueue = txDev:getTxQueue(0), ips = ARP_IP }
	}
	-- wait until all tasks are finished
	mg.waitForTasks()
	end

local function doArp()
	if not DST_MAC then
		log:info("Performing ARP lookup on %s", GW_IP)
		DST_MAC = arp.blockingLookup(GW_IP, 5)
		if not DST_MAC then
			log:info("ARP lookup failed, using default destination mac address")
			return
		end
	end
	log:info("Destination mac: %s", DST_MAC)
end


-- Source: https://stackoverflow.com/a/32167188
function shuffle(tbl) -- suffles numeric indices
    local len, random = #tbl, math.random ;
    for i = len, 2, -1 do
        local j = random( 1, i );
        tbl[i], tbl[j] = tbl[j], tbl[i];
    end
    return tbl;
end

local function fillUdpPacket(buf, len, port)
	buf:getUdpPacket():fill{
		ethSrc = queue,
		ethDst = DST_MAC,
		ip4Src = SRC_IP,
		ip4Dst = DST_IP,
		udpSrc = SRC_PORT,
		udpDst = port,
		pktLength = len
	}
end

function loadSlave(queue, ports, burst)
	--TODO Add Burst
	doArp()
	mg.sleepMillis(100) -- wait a few milliseconds to ensure that the rx thread is running
	local mem = memory.createMemPool(function(buf)
		fillUdpPacket(buf, port, PKT_SIZE)
	end)
	-- TODO: fix per-queue stats counters to use the statistics registers here
	local txCtr = stats:newManualTxCounter("TX All", "plain")
	-- a buf array is essentially a very thing wrapper around a rte_mbuf*[], i.e. an array of pointers to packet buffers
	local bufs = mem:bufArray()
	while mg.running() do
		-- allocate buffers from the mem pool and store them in this array
		bufs:alloc(PKT_SIZE)
		for i, buf in ipairs(bufs) do
			local pkt = buf:getUdpPacket()
			pkt.udp:setDstPort(ports[math.random(1,table.getn(ports))])
		end
		-- send packets
		bufs:offloadUdpChecksums()
		txCtr:updateWithSize(queue:send(bufs), PKT_SIZE)
	end
	txCtr:finalize()
end

function counterSlave(queue)
	-- the simplest way to count packets is by receiving them all
	-- an alternative would be using flow director to filter packets by port and use the queue statistics
	-- however, the current implementation is limited to filtering timestamp packets
	-- (changing this wouldn't be too complicated, have a look at filter.lua if you want to implement this)
	-- however, queue statistics are also not yet implemented and the DPDK abstraction is somewhat annoying
	local bufs = memory.bufArray()
	local ctrs = {}
	while mg.running(100) do
		local rx = queue:recv(bufs)
		for i = 1, rx do
			local buf = bufs[i]
			local pkt = buf:getUdpPacket()
			local port = pkt.udp:getDstPort()
			local ctr = ctrs[port]
			if not ctr then
				ctr = stats:newPktRxCounter("Port " .. port, "plain")
				ctrs[port] = ctr
			end
			ctr:countPacket(buf)
		end
		-- update() on rxPktCounters must be called to print statistics periodically
		-- this is not done in countPacket() for performance reasons (needs to check timestamps)
		for k, v in pairs(ctrs) do
			v:update()
		end
		bufs:freeAll()
	end
	for k, v in pairs(ctrs) do
		v:finalize()
	end
end


function timerSlave(txQueue, rxQueue, flows, rate, warmUp)
	doArp()
	local timestamper = ts:newUdpTimestamper(txQueue, rxQueue)
	local histogram = {}
        for i=1,flows do
                table.insert(histogram,hist:new())
        end
	mg.sleepMillis(1000+(1000*warmUp)) -- ensure that the load task is running and include WarmUp phase
	local flow = 0
	local rateLimit = timer:new(0.001)
  	local dstPort = tonumber(DST_PORT_BASE)
	while mg.running() do
		-- TODO Maybe iterate over the array instead of random as it is already randomly distributed
                local lat = timestamper:measureLatency(PKT_SIZE, function(buf)
						port=ports[math.random(1,table.getn(ports))]
                        fillUdpPacket(buf, PKT_SIZE, port)
                        flow = port - DST_PORT_BASE
                end)
                histogram[flow]:update(lat)
                rateLimit:wait()
                rateLimit:reset()
        end
        -- print the latency stats after all the other stuff
        mg.sleepMillis(300)
        for i=1,flows do
                histogram[i]:print()
                histogram[i]:save("histogram"..tostring(i)..".csv")
        end
end

