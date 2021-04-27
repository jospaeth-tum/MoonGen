--- Generates MoonSniff traffic, i.e. packets contain an identifier and a fixed bit pattern
--- Live mode and MSCAP mode require this type of traffic

local lm     = require "libmoon"
local device = require "device"
local memory = require "memory"
local ts     = require "timestamping"
local hist   = require "histogram"
local timer  = require "timer"
local log    = require "log"
local stats  = require "stats"
local bit    = require "bit"
local limiter = require "software-ratecontrol"

local MS_TYPE = 0b01010101
local band = bit.band

local DST_MAC 		= nil-- resolved via ARP on GW_IP or DST_IP, can be overriden with a string here
local SRC_IP_BASE	= "10.0.0.10"
local DST_IP		= "10.0.250.10"
local SRC_PORT		= 1234
local DST_PORT_BASE	= 1001

-- answer ARP requests for this IP on the rx port
-- change this if benchmarking something like a NAT device
local RX_IP		= DST_IP
-- used to resolve DST_MAC
local GW_IP		= "10.0.0.1"
-- used as source IP to resolve GW_IP to DST_MAC
local ARP_IP	= SRC_IP

function configure(parser)
	parser:description("Generate traffic which can be used by moonsniff to establish latencies induced by a device under test.")
	parser:argument("dev", "Devices to use."):args(2):convert(tonumber)
	parser:option("-v --fix-packetrate", "Approximate send rate in pps."):convert(tonumber):default(10000):target('fixedPacketRate')
	parser:option("-x --size", "Packet size in bytes."):convert(tonumber):default(100):target('packetSize')
	parser:option("-b --burst", "Generated traffic is generated with the specified burst size (default burst size 1)"):default(1):target("burstSize")
	parser:option("-w --warm-up", "Warm-up device by sending 1000 pkts and pausing n seconds before real test begins."):convert(tonumber):default(0):target('warmUp')
        parser:option("-f --flows", "Number of flows (1000 + flow as dst port)."):default(1):convert(tonumber):target('flows')

	return parser:parse()
end

function master(args)
	args.dev[1] = device.config { port = args.dev[1], txQueues = 2, rxQueues = 1 }
	args.dev[2] = device.config { port = args.dev[2], rxQueues = 2, txQueues = 1 }
	device.waitForLinks()
	local dev0tx = args.dev[1]:getTxQueue(0)
	local dev1rx = args.dev[2]:getRxQueue(0)

	stats.startStatsTask { txDevices = { args.dev[1] }, rxDevices = { args.dev[2] } }

	rateLimiter = limiter:new(dev0tx, "custom")
	local sender0 = lm.startTask("generateTraffic", dev0tx, args, rateLimiter)

	if args.warmUp > 0 then
		print('warm up active')
	end

	arp.startArpTask{
		-- run ARP on both ports
		{ rxQueue = args.dev[2]:getRxQueue(1), txQueue = args.dev[2]:getTxQueue(0), ips = RX_IP },
		-- we need an IP address to do ARP requests on this interface
		{ rxQueue = args.dev[1]:getRxQueue(0), txQueue = args.dev[1]:getTxQueue(1), ips = ARP_IP }
	}

	sender0:wait()
	lm.stop()
	lm.waitForTasks()
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

function generateTraffic(queue, args, rateLimiter)
	doArp()
	dstMAC = DST_MAC
	log:info("Trying to enable rx timestamping of all packets, this isn't supported by most nics")
	local pkt_id = 0
	local dstPort = tonumber(DST_PORT_BASE)
	local runtime = timer:new(args.time)
	local mempool = memory.createMemPool(function(buf)
		buf:getUdpPacket():fill {
			pktLength = args.packetSize,
			ethSrc = queue,
			ethDst = DST_MAC,
			ip4Src = SRC_IP_BASE,
			ip4Dst = DST_IP,
			udpSrc = SRC_PORT
		}
	end)
	local bufs = mempool:bufArray()
	counter = 0
	delay = 0
	while lm.running() do
		bufs:alloc(args.packetSize)

		for i, buf in ipairs(bufs) do
			local pkt = buf:getUdpPacket()
			-- for setters to work correctly, the number is not allowed to exceed 16 bit
			pkt.ip4:setID(band(pkt_id, 0xFFFF))
			pkt.payload.uint32[0] = pkt_id
			pkt.payload.uint8[4] = MS_TYPE
			pkt_id = pkt_id + 1
			numberOfPackets = numberOfPackets - 1
			counter = counter + 1
			if args.flows > 1 then
				pkt.udp:setDstPort(dstPort + (counter % args.flows))
			end

			if (args.warmUp > 0 and counter == 946) then
				delay =  (10000000000 / 8) * args.warmUp
				buf:setDelay(delay)
				delay = 0
			else
				delay =  delay + (10000000000 / args.fixedPacketRate / 8 - (args.packetSize + 4))
				if counter % args.burstSize == 0 then
					buf:setDelay(delay)
					delay = 0
				else
					buf:setDelay(0)
				end
			end
		end
		bufs:offloadIPChecksums()
		bufs:offloadUdpChecksums()
		rateLimiter:send(bufs)
			
		if args.warmUp > 0 and counter == 945 then
			lm.sleepMillis(1000 * args.warmUp)
		end
	end
end
