// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract IDSStorage {
    struct Log {
        uint256 timestamp;
        string ip;
    }

    Log[] public logs;

    function addLog(string memory _ip) public {
        logs.push(Log(block.timestamp, _ip));
    }

    function getLogs() public view returns (Log[] memory) {
        return logs;
    }
}
