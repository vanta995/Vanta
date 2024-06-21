// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

// Uncomment this line to use console.log
// import "hardhat/console.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/math/MathUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@uniswap/v2-periphery/contracts/interfaces/IUniswapV2Router02.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

struct StakeInfo {
    address user;
    uint currentAmount;
    uint[] buyAmounts;
}

contract Stake is
    Initializable,
    AccessControlEnumerableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable
{
    using SafeERC20Upgradeable for IERC20Upgradeable;

    bytes32 public constant MANAGE_ROLE = keccak256("MANAGE_ROLE");

    IUniswapV2Router02 public router;

    IERC20Upgradeable public mbk;
    IERC20Upgradeable public usdt;
    address public rewardDistribute;

    mapping(address => StakeInfo) stakeInfos;

    bytes32 public DOMAIN_SEPARATOR;

    //type: 1- statics reward; 2- thanksgiving reward; 3- management reward
    bytes32 private constant PERMIT_TYPEHASH =
        keccak256(
            abi.encodePacked(
                "Permit(address user,uint256 amount,uint256 order,uint256 period,uint256 reStake,uint256 nonce,uint256 deadline)"
            )
        );

    address public signer;

    mapping(address => uint) public nonces;

    event StakeEvent(
        address caller,
        uint mbkAmount,
        uint usdtAmount,
        uint mbkPrice,
        uint order,
        uint period,
        uint reStake
    );

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(MANAGE_ROLE) {}

    function initialize(
        IUniswapV2Router02 _router,
        IERC20Upgradeable _mbk,
        IERC20Upgradeable _usdt,
        address _rewardDistribute,
        address _signer
    ) public initializer {
        __AccessControlEnumerable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MANAGE_ROLE, msg.sender);

        router = _router;
        mbk = _mbk;
        usdt = _usdt;
        rewardDistribute = _rewardDistribute;

        signer = _signer;
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("Stake")),
                keccak256(bytes("1")),
                chainId,
                address(this)
            )
        );
    }

    function batchGrantRole(
        bytes32 role,
        address[] calldata accounts
    ) public onlyRole(getRoleAdmin(role)) {
        for (uint i = 0; i < accounts.length; i++) {
            _grantRole(role, accounts[i]);
        }
    }

    function batchRevokeRole(
        bytes32 role,
        address[] calldata accounts
    ) public onlyRole(getRoleAdmin(role)) {
        for (uint i = 0; i < accounts.length; i++) {
            _revokeRole(role, accounts[i]);
        }
    }

    function queryRoles(bytes32 role) public view returns (address[] memory) {
        uint roleNum = getRoleMemberCount(role);
        address[] memory accounts = new address[](roleNum);
        for (uint i = 0; i < roleNum; i++) {
            accounts[i] = getRoleMember(role, i);
        }
        return accounts;
    }

    function balance(address token) public view returns (uint256) {
        if (token == address(0)) {
            return address(this).balance;
        }
        return IERC20Upgradeable(token).balanceOf(address(this));
    }

    function withdrawErc20(
        address token,
        address to,
        uint256 amount
    ) public onlyRole(MANAGE_ROLE) {
        uint256 tokenBalance = IERC20Upgradeable(token).balanceOf(
            address(this)
        );
        require(tokenBalance >= amount, "ERROR:INSUFFICIENT");
        IERC20Upgradeable(token).safeTransfer(to, amount);
    }

    function queryUsdtByMbk(
        uint mbkAmount
    ) public view returns (uint usdtAmount) {
        address[] memory path = new address[](2);
        path[0] = address(mbk);
        path[1] = address(usdt);
        uint[] memory amounts = router.getAmountsOut(1e18, path);
        require(amounts.length > 1, "Bot: GET_AMOUNT_OUT_ERROR");
        usdtAmount = (amounts[1] * mbkAmount) / 1e18;
    }

    function queryMbkByUsdt(
        uint usdtAmount
    ) public view returns (uint mbkAmount) {
        address[] memory path = new address[](2);
        path[0] = address(usdt);
        path[1] = address(mbk);
        uint[] memory amounts = router.getAmountsOut(1e18, path);
        require(amounts.length > 1, "Bot: GET_AMOUNT_OUT_ERROR");
        mbkAmount = (amounts[1] * usdtAmount) / 1e18;
    }

    function setRouter(
        IUniswapV2Router02 _router
    ) public onlyRole(MANAGE_ROLE) {
        router = _router;
    }

    function setMbk(IERC20Upgradeable _mbk) public onlyRole(MANAGE_ROLE) {
        mbk = _mbk;
    }

    function setUsdt(IERC20Upgradeable _usdt) public onlyRole(MANAGE_ROLE) {
        usdt = _usdt;
    }

    function setRewardDistribute(
        address _rewardDistribute
    ) public onlyRole(MANAGE_ROLE) {
        rewardDistribute = _rewardDistribute;
    }

    function updateSigner(address _signer) public onlyRole(MANAGE_ROLE) {
        signer = _signer;
    }

    function stake(bytes calldata data) public nonReentrant {
        (
            address user,
            uint256 amount,
            uint256 order,
            uint256 period,
            uint256 reStake,
            uint256 nonce,
            uint256 deadline,
            bytes memory signature
        ) = abi.decode(
                data,
                (
                    address,
                    uint256,
                    uint256,
                    uint256,
                    uint256,
                    uint256,
                    uint256,
                    bytes
                )
            );
        require(amount % (20 * 1e18) == 0, "Stake: amount error");
        StakeInfo storage stakeInfo = stakeInfos[msg.sender];
        require(
            amount >= stakeInfo.currentAmount,
            "Bot: less than last time buy amount"
        );
        stakeInfo.currentAmount = amount;
        stakeInfo.buyAmounts.push(amount);

        require(user == msg.sender, "Stake: invalid user");
        require(nonce == nonces[msg.sender], "Stake: invalid nonce");
        require(block.timestamp <= deadline, "Stake: time out");
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);
        bytes32 signHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        PERMIT_TYPEHASH,
                        user,
                        amount,
                        order,
                        period,
                        reStake,
                        nonce,
                        deadline
                    )
                )
            )
        );
        (address realSigner, ECDSA.RecoverError errorEnum ) = ECDSA.tryRecover(
            signHash,
            v,
            r,
            s
        );
        require(
            signer == realSigner && errorEnum == ECDSA.RecoverError.NoError,
            "ERROR:INVALID_REQUEST"
        );
        nonces[msg.sender]++;
        //send token
        mbk.safeTransferFrom(user, rewardDistribute, amount);
        emit StakeEvent(
            user,
            amount,
            queryUsdtByMbk(amount),
            queryUsdtByMbk(1 * 1e18),
            order,
            period,
            reStake
        );
    }

    function splitSignature(
        bytes memory sig
    ) internal pure returns (uint8, bytes32, bytes32) {
        require(sig.length == 65, "Not Invalid Signature Data");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        return (v, r, s);
    }
}
