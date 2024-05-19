def Recovery1(pk,sk,t):
        
    shares=[]
    for i in range(0,t):
        sh=TTP_decrypt(i+1, pk[i], sk[i])
        shares.extend([sh])

    sequence = list(range(2, t+2, 2))
    for i in sequence:
        ii=int((2*i)/3)+1
        ss=shares[:ii]
        


        t1 = time.time()
        result=PVSS.Reconstruct(ss)    #off-chain
        elapsed_time_ms = (time.time() - t1) * 1000
        print("number of ttp",i)
        print(f'enc:{elapsed_time_ms:.4f}ms')
    #result=Contract.functions.Reconstruction().call()
    
    # 将整数转换为bytes类型
    # 128位的AES密钥