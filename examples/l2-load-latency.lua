local mg     = require "moongen"
local memory = require "memory"
local device = require "device"
local ts     = require "timestamping"
local stats  = require "stats"
local hist   = require "histogram"

local ETH_DST	= "11:12:13:14:15:16"

local function getRstFile(...)
	local args = { ... }
	for i, v in ipairs(args) do
		result, count = string.gsub(v, "%-%-result%=", "")
		if (count == 1) then
			return i, result
		end
	end
	return nil, nil
end

function configure(parser)
	parser:description("Generates bidirectional CBR traffic with hardware rate control and measure latencies.")
	parser:argument("dev1", "Device to transmit/receive from."):convert(tonumber)
	parser:argument("dev2", "Device to transmit/receive from."):convert(tonumber)
	parser:option("-r --rate", "Transmit rate in Mbit/s."):default(10000):convert(tonumber)
	parser:option("-p --pktrate", "Transmit rate in pps."):default(0):convert(tonumber)
	parser:option("-s --pktsize", "Packetsize in bytes (incl. crc)."):default(64):convert(tonumber)
	parser:option("-f --file", "Filename of the latency histogram."):default("histogram.csv")
end

function master(args)
	local dev1 = device.config({port = args.dev1, txQueues = 2})
	local dev2 = device.config({port = args.dev2, rxQueues = 2})
	device.waitForLinks()

	pktsize = args.pktsize
	if args.pktsize < 64 then
		pktsize = 64
	end

	rate = args.rate
	if args.pktrate > 0 then
		rate = (args.pktrate * (pktsize) * 8) / 1000000
	end
	dev1:getTxQueue(0):setRate(rate)
	mg.startTask("loadSlave", dev1:getTxQueue(0), pktsize)
	--if dev1 ~= dev2 then
	--	mg.startTask("loadSlave", dev2:getTxQueue(0), pktsize)
	--end
	--stats.startStatsTask{dev1}
	mg.startSharedTask("timerSlave", dev1:getTxQueue(1), dev2:getRxQueue(1), args.file)
	mg.waitForTasks()
end

function loadSlave(queue, pktsize)
	local mem = memory.createMemPool(function(buf)
		buf:getEthernetPacket():fill{
			ethSrc = txDev,
			ethDst = ETH_DST,
			ethType = 0x1234
		}
	end)
	local bufs = mem:bufArray()
	while mg.running() do
		bufs:alloc(pktsize - 4)
		queue:send(bufs)
	end
end

function timerSlave(txQueue, rxQueue, histfile)
	local txCtr = stats:newDevTxCounter(txQueue, "CSV", 'throughput-tx.csv')
	local rxCtr = stats:newDevRxCounter(rxQueue, "CSV", 'throughput-rx.csv')

	local timestamper = ts:newTimestamper(txQueue, rxQueue)
	local hist = hist:new()
	mg.sleepMillis(1000) -- ensure that the load task is running
	while mg.running() do
		hist:update(timestamper:measureLatency(function(buf) buf:getEthernetPacket().eth.dst:setString(ETH_DST) end))
		txCtr:update()
		rxCtr:update()
	end
	txCtr:finalize()
	rxCtr:finalize()
	hist:print()
	hist:save(histfile)
end
