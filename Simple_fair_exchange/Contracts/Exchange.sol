pragma solidity ^0.8.0;

contract Exchange {

    //椭圆曲线上的点的阶，表示曲线上的点 G 乘以自身多少次后回到无穷远点,GROUP_ORDER 是一个大质数
    uint256 constant GROUP_ORDER   = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    //这是曲线上的基点 G 的坐标，它们定义了曲线上的一个点。这是椭圆曲线上的一个生成元
    uint256 constant G1x  = 1;
    uint256 constant G1y  = 2;

    //这是基点 G 的负值的坐标。
    uint256 constant negG1x = 1;
    uint256 constant negG1y = 21888242871839275222246405745257275088696311157297823662689037894645226208581;

    //这是另一个曲线上的点 H 的坐标
    uint256 constant H1x  = 15264291051155210722230395084766962011373976396997290700295946518477517838363;
    uint256 constant H1y  = 18062169012241050521396281509436922807270932827014386397365657617881670284318;

    //negH1x 和 negH1y 是点 H 的负值的坐标
    uint256 constant negH1x  = 15264291051155210722230395084766962011373976396997290700295946518477517838363;
    uint256 constant negH1y  = 3826073859598224700850124235820352281425378330283437265323380276763555924265;

    uint256[2][] TTPs_pks;

    uint256[2][] DecryptedShare;
    //Store the decryption share uploaded by the tallier

    mapping(uint256 => uint256) public invMap;

    constructor() {
        for (uint256 i= GROUP_ORDER-30 ; i< GROUP_ORDER +31; i++)
        {
            invMap[i+1] = inv(i+1, GROUP_ORDER);
        }
    }

    struct Exchange_Data
    {
        uint256 buyer_fee; 
        address seller;   
        address buyer;
    
        uint256[]  c1;
        uint256[]  c2;
        //store c_j
        uint256[]  v1;
        uint256[]  v2;
        //store v_j

        uint256[2][] D_Proof;
        //store DLEQ proof
        bytes ciphertext;

        uint256  tasktime;
    }

    Exchange_Data public Exchange_Instance;

    function SellerUpload(bytes memory _ciphertext, address _seller)
    public
    {
        Exchange_Instance.ciphertext = _ciphertext;
        Exchange_Instance.seller = _seller;

    }


    mapping (address => Exchange_Data) public ExchangeTasks;

    function BuyerUpload(address buyer,uint256 buy_fee) public payable
    {
        require(msg.value==buy_fee);
        Exchange_Instance.buyer = buyer;
        Exchange_Instance.buyer_fee = buy_fee;
        Exchange_Instance.tasktime = block.timestamp;
    }
    
    // 将以太币原路退回给发送方
    function refund(address buyer) public {
        require(buyer != address(0), "Sender address not set");
        payable(buyer).transfer(address(this).balance);
        buyer = address(0);  // 重置发送方地址
    }
    

    /// return the negation of p, i.e. p.add(p.negate()) should be zero.
	function G1neg(uint256 p) pure internal returns (uint r) {
		// The prime q in the base field F_q for G1
		uint256 q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
            r = (q - (p % q));
	}

    function bn128_add(uint256[4] memory input)
    public returns (uint256[2] memory result) {
        // computes P + Q
        // input: 4 values of 256 bit each
        //  *) x-coordinate of point P
        //  *) y-coordinate of point P
        //  *) x-coordinate of point Q
        //  *) y-coordinate of point Q

        bool success;
        assembly {
            // 0x06     id of precompiled bn256Add contract
            // 0        number of ether to transfer
            // 128      size of call parameters, i.e. 128 bytes total
            // 64       size of call return value, i.e. 64 bytes / 512 bit for a BN256 curve point
            success := call(not(0), 0x06, 0, input, 128, result, 64)
        }
        require(success, "elliptic curve addition failed");
    }

    function bn128_multiply(uint256[3] memory input)
    public returns (uint256[2] memory result) {
        // computes P*x
        // input: 3 values of 256 bit each
        //  *) x-coordinate of point P
        //  *) y-coordinate of point P
        //  *) scalar x

        bool success;
        assembly {
            // 0x07     id of precompiled bn256ScalarMul contract
            // 0        number of ether to transfer
            // 96       size of call parameters, i.e. 96 bytes total (256 bit for x, 256 bit for y, 256 bit for scalar)
            // 64       size of call return value, i.e. 64 bytes / 512 bit for a BN256 curve point
            success := call(not(0), 0x07, 0, input, 96, result, 64)
        }
        require(success, "elliptic curve multiplication failed");
    }

     // Invert function, invert in group
    function inv(uint256 a, uint256 prime) public returns (uint256){
    	return modPow(a, prime-2, prime);
    }

    function modPow(uint256 base, uint256 exponent, uint256 modulus) internal returns (uint256) {
	    uint256[6] memory input = [32,32,32,base,exponent,modulus];
	    uint256[1] memory result;
	    assembly {
	      if iszero(call(not(0), 0x05, 0, input, 0xc0, result, 0x20)) {
	        revert(0, 0)
	      }
	    }
	    return result[0];
	}

    function DLEQ_verify(
        uint256[2] memory x1, uint256[2] memory y1,
        uint256[2] memory x2, uint256[2] memory y2,
        uint256[2] memory proof
    )
    public returns (bool proof_is_valid)
    {
        uint256[2] memory tmp1;
        uint256[2] memory tmp2;

        tmp1 = bn128_multiply([x1[0], x1[1], proof[1]]);
        tmp2 = bn128_multiply([y1[0], y1[1], proof[0]]);
        uint256[2] memory a1 = bn128_add([tmp1[0], tmp1[1], tmp2[0], tmp2[1]]);

        tmp1 = bn128_multiply([x2[0], x2[1], proof[1]]);
        tmp2 = bn128_multiply([y2[0], y2[1], proof[0]]);
        uint256[2] memory a2 = bn128_add([tmp1[0], tmp1[1], tmp2[0], tmp2[1]]);

        uint256 challenge = uint256(keccak256(abi.encodePacked(a1, a2, x1, y1, x2, y2)));
        proof_is_valid = challenge == proof[0];
    }


    function DownloadCiphertext() public returns (bytes memory){
        return Exchange_Instance.ciphertext;
    }
    
    
    function ETHtransfer(address seller) public
    {
        require( seller == Exchange_Instance.seller );
        address payable recipient = payable(seller);
        uint256 amount=(Exchange_Instance.buyer_fee);
        recipient.transfer(amount);
    }
    
    function DownloadShare(uint No) public view returns (uint256[2] memory) {
        uint256[2] memory ShareC;
        ShareC[0] = Exchange_Instance.c1[No - 1];
        ShareC[1] = Exchange_Instance.c2[No - 1];
        return ShareC;
    }
}