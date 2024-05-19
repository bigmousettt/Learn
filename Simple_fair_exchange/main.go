// 使用方法替换gnark-tests-main/solidity/contract文件夹下的main.go函数
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"regexp"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/consensys/gnark/std/hash/mimc"
)

// 存储groth的结构体——————以结构体的形式放入json文件中（一个结构体对应一个poof和input）
type Groth16_output struct {
	G_proof []*big.Int
	G_input [1]*big.Int
}

// 定义电路的变量
// 定义电路

type Circuit struct {
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	// 这行代码调用了 api 对象的 Println 方法，输出了 circuit 结构体中的 Hash 成员变量的值。
	api.Println(circuit.Hash)
	//这行代码输出了 circuit 结构体中的 PreImage 成员变量的值。
	api.Println(circuit.PreImage)
	//这行代码创建了一个 MiMC 对象，并且将 api 对象传递给它。MiMC 是一个密码学哈希函数，这里使用它来计算 circuit 结构体中的 PreImage 的哈希值。
	mimc, _ := mimc.NewMiMC(api)
	//将 circuit 结构体中的 PreImage 写入到 MiMC 对象中。
	mimc.Write(circuit.PreImage)
	//输出 MiMC 对象的哈希值。
	api.Println(mimc.Sum())
	//这行代码断言 circuit 结构体中的 Hash 成员变量的值与 MiMC 计算得到的哈希值相等，如果不相等则会触发错误。
	api.AssertIsEqual(circuit.Hash, mimc.Sum())
	return nil
}

func mimcHash(data []byte) string {
	f := bn254.NewMiMC()
	//f.Reset()
	f.Write(data)
	hash := f.Sum(nil)
	hashInt := big.NewInt(0).SetBytes(hash)
	return hashInt.String()
}

func Str2Byte(v string) []byte {
	var f fr.Element
	f.SetString(v)
	b := f.Bytes()
	return b[:]
}

var Alice_Hash string = "789798794465798431564"

var Bob_Hash string = "7897987944688885798431564"

func main() {
	//fmt.Println("......................................... zkSNARKs Verify begin .................................................")

	
	//创建电路——————————————————————————————————————（替换电路）——————————————（替换处）
	var circuit Circuit
	//创建一个证明————————————————————————————————————（替换证明）—————————————（替换处）
	var assignment1 = Circuit{
		PreImage: Str2Byte(Alice_Hash),
		Hash:     mimcHash(Str2Byte(Alice_Hash)),
	}

	fileContent, err := ioutil.ReadFile("zkSNARKs_Hash.txt")
	if err != nil {
		fmt.Println("读取文件时发生错误:", err)
		return
	}

	// 将字节切片转换为字符串
	Alice_Hash = string(fileContent)
	//fmt.Println(Alice_Hash)

	re := regexp.MustCompile("[0-9]+")               // 匹配一个或多个数字
	tempstring11 := re.FindAllString(Alice_Hash, -1) // 搜索字符串中匹配的所有数字
	Alice_Hash = strings.Join(tempstring11, "")
	//fmt.Println(Alice_Hash)
	assignment1.PreImage = Str2Byte(Alice_Hash)
	assignment1.Hash = mimcHash(Str2Byte(Alice_Hash))

	// 根据电路setup groth16
	rcls, pk, err := generateGroth16(circuit)
	if err != nil {
		log.Fatal("groth16 error:", err)
	}

	//生成证明并保留参数至json文件
	err = new_groth_proof1(assignment1, rcls, pk, "gorth16_output") //"groth_output"，json文件名——————（替换文件名）——————（替换处）
	if err != nil {
		log.Fatal("groth16 error:", err)
	}
	//fmt.Println(Alice_grothVerify())
	// fmt.Println("zkSNARKs verify resunlt:", Alice_grothVerify())
}

// 初始化函数：根据电路setup groth16
func generateGroth16(circuit Circuit) (r1cs1 constraint.ConstraintSystem, pk groth16.ProvingKey, err error) {

	r1cs1, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, err
	}
	//生成groth的pk和vk
	pk, vk, err := groth16.Setup(r1cs1)
	if err != nil {
		return nil, nil, err
	}
	{
		f, err := os.Create("cubic.g16.vk")
		if err != nil {
			return nil, nil, err
		}
		_, err = vk.WriteRawTo(f)
		if err != nil {
			return nil, nil, err
		}
	}
	{
		f, err := os.Create("cubic.g16.pk")
		if err != nil {
			return nil, nil, err
		}
		_, err = pk.WriteRawTo(f)
		if err != nil {
			return nil, nil, err
		}
	}

	{
		f, err := os.Create("contract_g16.sol")
		if err != nil {
			return nil, nil, err
		}
		err = vk.ExportSolidity(f)
		if err != nil {
			return nil, nil, err
		}
	}
	return r1cs1, pk, nil
}

// groth生成参数函数：产生groth的proof和input
func new_groth_proof1(assignment Circuit, r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, name string) error {

	//创建一个见证者
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	//生成证明
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		return err
	}

	// 获取证明的字节序列
	const fpSize = 4 * 8
	var buf bytes.Buffer
	proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()
	mergedArray := make([]*big.Int, 8) //存储proof
	var input [1]*big.Int              // 定义数组input，用于存储公开的见证（witness）值
	mergedArray[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	mergedArray[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	mergedArray[2] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	mergedArray[3] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	mergedArray[4] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	mergedArray[5] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	mergedArray[6] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	mergedArray[7] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	//input[0] = new(big.Int).SetUint64(35) // 设置公开见证的值为35，这通常对应于证明中需要验证的某个具体值（替换input参数）
	input[0], _ = new(big.Int).SetString(mimcHash(Str2Byte(Alice_Hash)), 10)
	//将参数写入结构体
	groth16_output := Groth16_output{
		G_proof: mergedArray,
		G_input: input,
	}

	// 将结构体序列化为JSON并写入文件
	file, err := os.Create(name + ".json")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(groth16_output); err != nil {
		log.Fatal(err)
	}
	return nil
}

// func Alice_grothVerify() bool {
// 	cmd := exec.Command("/usr/bin/python3", "./verify.py") //go calls python verify.py directly
// 	stdout, _ := cmd.Output()
// 	output := strings.TrimSpace(string(stdout))
// 	if output == "True" {
// 		return true
// 	} else {
// 		return false
// 	}
// }

/*
func Bob_grothVerify() bool {
	cmd := exec.Command("/usr/bin/python3", "./verify_Bob.py") //go calls python verify.py directly
	stdout, _ := cmd.Output()
	output := strings.TrimSpace(string(stdout))
	if output == "True" {
		return true
	} else {
		return false
	}
}
*/
