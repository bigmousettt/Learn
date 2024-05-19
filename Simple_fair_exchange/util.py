def Point2IntArr(x):  # transform Point tuple/list to int[]
    ints = [int(num) for num in x]
    return ints

def Dataconvert(res):  # Data conversion functions for bilinear pairing on-chain
    c1 = []
    c2 = []
    # Data format conversion to separate c(x,y) into separate arrays
    v1 = []
    v2 = []
    # Data format conversion to separate v(x,y) into separate arrays

    c1.extend(int(res["c"][i][0]) for i in range(0, len(res["c"])))
    c2.extend(int(res["c"][i][1]) for i in range(0, len(res["c"])))
    v1.extend(int(res["v"][i][0]) for i in range(0, len(res["c"])))
    v2.extend(int(res["v"][i][1]) for i in range(0, len(res["c"])))
    return {"c1": c1, "c2": c2, "v1": v1, "v2": v2}  # c1 is x of c, c2 is y of c. And v1,v2,s1,s2 so on...

def U_jdataconvert(U_j):  # Data format conversion to separate U (x,y) into separate arrays
    U_j1 = []             # U_j1 is x of U_j and U_j2 is y of U_j
    U_j2 = []
    U_j1.extend(int(U_j[i][0]) for i in range(0, len(U_j)))
    U_j2.extend(int(U_j[i][1]) for i in range(0, len(U_j)))
    return{"U_j1":U_j1,"U_j2":U_j2}


def lagrange_coefficient(i: int,recIndex) -> int:
    result = 1
    for j in recIndex:
        # print(j)
        # j=j-1ss
        if i != j:
            result *= j * sympy.mod_inverse((j - i) % CURVE_ORDER, CURVE_ORDER)
            result %= CURVE_ORDER
    return result