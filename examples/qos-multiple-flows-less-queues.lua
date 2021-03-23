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

local DST_MAC		= "54:54:00:00:00:00" -- resolved via ARP on GW_IP or DST_IP, can be overriden with a string here
local SRC_IP	  	= "10.0.0.10"
local DST_IP		= "10.0.250.10"
local SRC_PORT		= 1234
local DST_PORT_BASE	= 1000

function configure(parser)
	parser:description("Generates two flows of traffic and compares them. This example requires an ixgbe NIC due to the used hardware features.")
	parser:argument("txDev", "Device to transmit from."):convert(tonumber)
	parser:argument("rxDev", "Device to receive from."):convert(tonumber)
	parser:option("-r --rate", "Transmit rate in Mbit/s."):args("*"):default(10000):convert(tonumber)
	parser:option("-v --vlan", "VLANs per Flow"):args("*"):default(-1):convert(tonumber)
	parser:option("-m --mac", "MAC per VLAN"):args("*"):default(-1)
	parser:option("-b --burst", "Burst in bytes"):args("*"):default(10000):convert(tonumber)
	parser:option("-f --flows", "Number of flows (randomized dest Port)."):default(4):convert(tonumber)
	parser:option("-w --warmup", "Warmup-phase in seconds"):default(0):convert(tonumber)
	parser:option("-s --size", "Packet size."):default(84):convert(tonumber)
end

local function tableOfFlows(flows, rate)
    local flow_table = {}
	for i=1,flows do
		for x = 1, rate[i]*1000 do
			table.insert(flow_table, i)
		end
	end
	flow_table = shuffle(flow_table)
	return flow_table
end

-- Source: https://stackoverflow.com/questions/8695378/how-to-sum-a-table-of-numbers-in-lua
function sum(t)
    local sum = 0.0
    for k,v in pairs(t) do
        sum = sum + v
    end

    return sum
end


function master(args)
	if args.flows ~= (table.getn(args.rate) or table.getn(args.burst) or table.getn(args.vlan)) then
		log:error("Rate and burst are not matching the numbers of flows")
		return -1 -- Error as we have no result here, we need one definition per flow
	end
	local txDev, rxDev
	txDev = device.config{port = args.txDev, rxQueues = 1, txQueues = 3 }
	rxDev = device.config{port = args.rxDev, rxQueues = 3, txQueues = 1 }
	-- wait until the links are up
	device.waitForLinks()
	for i=1,args.flows,1
	do
		log:info("Sending Flow %g with %d MBit/s traffic and Burst %d to UDP port %d", i, args.rate[i], args.burst[i], DST_PORT_BASE + i)
	end
	txDev:getTxQueue(0):setRate(sum(args.rate))
    local flows = tableOfFlows(args.flows, args.rate)
	-- Starting the Tasks for the Queues
	mg.startTask("loadSlave", txDev:getTxQueue(0), flows, args.burst[i], args.size, args.vlan, args.mac)
	-- count the incoming packets
	mg.startTask("counterSlave", rxDev:getRxQueue(0))
	-- measure latency from a second queue
	mg.startSharedTask("timerSlave", txDev:getTxQueue(1), rxDev:getRxQueue(1), args.flows, flows, args.warmup, args.size, args.vlan, args.mac)
	-- wait until all tasks are finished
	mg.waitForTasks()
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

local function fillUdpPacket(buf, len, port, dst_mac)
	buf:getUdpPacket():fill{
		ethSrc = queue,
		ethDst = dst_mac,
		ip4Src = SRC_IP,
		ip4Dst = DST_IP,
		udpSrc = SRC_PORT,
		udpDst = port,
		pktLength = len
	}
end

-------------------------------------------------------------------------------
-- Converts a MAC address from its string representation to a numeric one, in
-- network byte order.
-- address  : The address to convert.
-------------------------------------------------------------------------------
function convertMacAddress(address)
	  local bytes = {string.match(address,
                    '(%x+)[-:](%x+)[-:](%x+)[-:](%x+)[-:](%x+)[-:](%x+)')}

    local convertedAddress = 0
    for i = 1, 6 do
        convertedAddress = convertedAddress +
                           tonumber(bytes[i], 16) * 256 ^ (i - 1)
    end
    return convertedAddress
end

function loadSlave(queue, flows, burst, size, vlan, mac)
	mg.sleepMillis(100) -- wait a few milliseconds to ensure that the rx thread is running
	local mem = memory.createMemPool(function(buf)
		fillUdpPacket(buf, size, port, DST_MAC)
	end)
	local txCtr = stats:newDevTxCounter(queue, "plain")
	-- a buf array is essentially a very thing wrapper around a rte_mbuf*[], i.e. an array of pointers to packet buffers
	local bufs = mem:bufArray()
	local counter = 0
	local numFlowEntries = table.getn(flows)
	while mg.running() do
		-- allocate buffers from the mem pool and store them in this array
		bufs:alloc(size)
		for i, buf in ipairs(bufs) do
			local pkt = buf:getUdpPacket()
			pkt.udp:setDstPort(DST_PORT_BASE + flows[counter+1])
			pkt.eth:setDst(convertMacAddress(mac[vlan[flows[counter+1]]]))
			buf:setVlan(vlan[flows[counter+1]])
			counter = incAndWrap(counter, numFlowEntries)
		end
		-- send packets
		bufs:offloadUdpChecksums()
		queue:send(bufs)
		txCtr:update()
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


function timerSlave(txQueue, rxQueue, flows, flowTable, warmUp, size, vlan, mac)
	local timestamper = ts:newUdpTimestamper(txQueue, rxQueue)
	local histogram = {}
        for i=1,flows do
                table.insert(histogram,hist:new())
        end
	mg.sleepMillis(1000+(1000*warmUp)) -- ensure that the load task is running and include WarmUp phase
	local flow = 0
	local counter = 0
	local rateLimit = timer:new(0.001)
	while mg.running() do
                local lat = timestamper:measureLatency(size, function(buf)
						port=DST_PORT_BASE + flowTable[counter+1]
                        fillUdpPacket(buf, PKT_SIZE, port, mac[vlan[flowTable[counter+1]]])
                        flow = flowTable[counter+1]
						buf:setVlan(vlan[flow])
						counter = incAndWrap(counter, table.getn(flowTable))
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

