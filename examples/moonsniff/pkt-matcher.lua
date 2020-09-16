--- This file holds a function which should be customized to serve your needs for packet matching

local lm        = require "libmoon"
local memory    = require "memory"
local log       = require "log"
local dpdk      = require "dpdk"
local pcap      = require "pcap"

local ffi    = require "ffi"
local C = ffi.C

local MS_TYPE = 0b01010101

--- Extracts data from an mbuf into a scratchpad
--- Depending on if the packet is a pre-DuT or post-DuT packet this function may need to behave differently
--- This may be useful when the DuT changes packets in a deterministic way
--
-- @param mbuf, the mbuf containing the packet
-- @param scratchpad, array to copy the slected data to
-- @param size, the size of the scratchpad in bytes
-- @param pre, true if pre-DuT packet, false otherwise
return function(mbuf, scratchpad, size, pre)
	local filled = 0 -- the number of bytes filled in the scratchpad

	----------------------------
	-- customize below here

	--pkt = mbuf:getEthernetPacket()
	--ethertype = pkt.eth:getType()
	--if ethertype == 0x800 then
	--	pkt = mbuf:getIP4Packet()
	--	srcip = pkt.ip4:getSrc()
	--	dstip = pkt.ip4:getDst() 
	--	proto = pkt.ip4:getProtocol()
	--	if proto == 0x6 then
	--		pkt = mbuf:getTcpPacket()
        --                srcprt = pkt.tcp:getSrcPort()
        --                dstprt = pkt.tcp:getDstPort()
	--		scratchpad[0] = proto % 256
	--		scratchpad[1] = (proto / 256) % 256
	--		scratchpad[2] = srcip % 256
	--		scratchpad[3] = (srcip / 256) % 256
	--		scratchpad[4] = (srcip / 256 / 256) % 256
	--		scratchpad[5] = (srcip / 256 / 256 / 256) % 256
	--		scratchpad[6] = dstip % 256
	--		scratchpad[7] = (dstip / 256) % 256
	--		scratchpad[8] = (dstip / 256 / 256) % 256
	--		scratchpad[9] = (dstip / 256 / 256 / 256) % 256
	--		scratchpad[10] = srcprt % 256
	--		scratchpad[11] = (srcprt / 256) % 256
	--		scratchpad[12] = dstprt % 256
	--		scratchpad[13] = (dstprt / 256) % 256
	--		--for i=0,13 do 
	--		--	print("[" .. i .. "]: " .. scratchpad[i])
	--		--end
	--              filled = 14
	--	else
	--		return filled
	--	end
	--else
	--	print("packet type not implemented")
	--	return filled
	--end

	pkt = mbuf:getEthernetPacket()
	ffi.copy(scratchpad, pkt.payload.uint8, 40)
	filled = 40

	--if pkt.payload.uint8[4] == MS_TYPE then
	--	ffi.copy(scratchpad, pkt.payload.uint8, 4)
	--	filled = 4
	--else
	--	print("Non moonsniff packet detected")
	--end

	-- customize above here
	----------------------------

	-- make sure we did not overfill the scratchpad
	if filled > size then log:err("UDF exceeded scratchpad size!") end

	return filled
end
