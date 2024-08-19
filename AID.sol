// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract AID is Ownable, ERC20Burnable {
    uint256 public pancakeBuyFeeRate;
    uint256 public pancakeSellFeeRate;
    address public pancakeFeeReceiver;
    address public pair;

    constructor() Ownable(msg.sender) ERC20("AID", "AID") {
        _mint(msg.sender, 100_000_000 ether);
    }

    function setFee(uint256 _pancakeBuyFeeRate, uint256 _pancakeSellFeeRate, address _pancakeFeeReceiver) external onlyOwner {
        require(_pancakeBuyFeeRate <= 1000, "invalid buy fee rate");
        require(_pancakeSellFeeRate <= 1000, "invalid buy fee rate");

        pancakeBuyFeeRate = _pancakeBuyFeeRate;
        pancakeSellFeeRate = _pancakeSellFeeRate;
        pancakeFeeReceiver = _pancakeFeeReceiver;
    }

    function setPair(address _pair) external onlyOwner {
        pair = _pair;
    }

    function _update(address from, address to, uint256 amount) internal override {
        if (from == pair && pancakeBuyFeeRate > 0) {
            uint256 fee = (amount * pancakeBuyFeeRate) / 1000;
            super._update(from, pancakeFeeReceiver, fee);
            amount -= fee;
        } else if (to == pair && pancakeSellFeeRate > 0) {
            uint256 fee = (amount * pancakeSellFeeRate) / 1000;
            amount -= fee;
            super._update(from, pancakeFeeReceiver, fee);
        }
        super._update(from, to, amount);
    }
}
