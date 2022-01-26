package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/alinush/go-mcl"
)

type PublicParams struct {
	n                        int
	pp_generators_alpha      []mcl.G1
	pp_generators_alpha_beta []mcl.G1
	vp_generators_alpha      []mcl.G2
	vp_generators_beta       []mcl.G2
	vp_gt_elt                mcl.GT
	g1                       mcl.G1
	g2                       mcl.G2
}

type Commitment struct {
	commit_c2 mcl.G1
	commit_c1 []mcl.G1
}

type InnerProof struct {
	inner_proof_content mcl.G1
}

type OuterProof struct {
	outer_proof_content mcl.G1
}

func IntToBytes(intNum int) []byte {
	uint16Num := uint16(intNum)
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, uint16Num)
	return buf.Bytes()
}

//one-dimension hash
func dim2Hash(
	commits []mcl.G1,
	set [][]int, //S
	value_sub_vector [][]mcl.Fr, //M[S]
	n int,
) []mcl.Fr {
	commitLen := len(commits)
	if commitLen == 1 {
		frOne := make([]mcl.Fr, 1)
		frOne[0].SetInt64(1)
		return frOne
	}
	// tmp = \{c_i, \mathcal{C}(S_i), \bm{M}_i[\mathcal{C}(S_i)]\}_{i\in \bm{S}_{(1)}}
	tmp := make([]byte, 0)
	for i := 0; i < commitLen; i++ {
		//add serialized commitment to tmp
		tmp = append(tmp, commits[i].Serialize()...)

		//add set[i] to tmp
		for j := 0; j < len(set[i]); j++ {
			tmp = append(tmp, IntToBytes(set[i][j])...)
		}

		// if the set leng does not mathc values, return an error
		if len(set[i]) != len(value_sub_vector[i]) {
			fmt.Println("length of set[i] and value_sub_vector[i] does not match")
		}

		//add set[i] to tmp
		for j := 0; j < len(set[i]); j++ {
			if set[i][j] >= n {
				fmt.Println("Invalid Index in set")
			}
			tmp = append(tmp, value_sub_vector[i][j].Serialize()...)
		}
	}

	hashRes := make([]mcl.Fr, commitLen)

	var tmpFr mcl.Fr
	tmpFr.SetHashOf(tmp)
	tmpHash := tmpFr.Serialize()
	for i := 0; i < commitLen; i++ {
		finalBytes := append(IntToBytes(i), tmpHash...)
		hashRes[i].SetHashOf(finalBytes)
	}
	return hashRes
}

func dim1Hash(
	commit mcl.G1,
	set []int,
	value_sub_vector []mcl.Fr,
	n int) []mcl.Fr {
	setLen := len(set)
	if setLen != len(value_sub_vector) {
		fmt.Println("length of set and value_sub_vector does not match")
	}

	if setLen == 1 {
		frOne := make([]mcl.Fr, 1)
		frOne[0].SetInt64(1)
		return frOne
	}

	for _, eInSet := range set {
		if eInSet >= n {
			fmt.Println("Invalid Index")
		}
	}
	//tmp = c_i, \mathcal{C}(S_i), \bm{M}_i[\mathcal{C}(S_i)]
	tmp := make([]byte, 0)
	//add serialized commitment to tmp
	tmp = append(tmp, commit.Serialize()...)

	//add set to tmp
	for j := 0; j < setLen; j++ {
		tmp = append(tmp, IntToBytes(set[j])...)
	}

	//add set[i] to tmp
	for j := 0; j < setLen; j++ {
		if set[j] >= n {
			fmt.Println("Invalid Index in set")
		}
		tmp = append(tmp, value_sub_vector[j].Serialize()...)
	}

	hashRes := make([]mcl.Fr, setLen)
	for i := 0; i < setLen; i++ {
		finalBytes := append(IntToBytes(i), tmp...)
		hashRes[i].SetHashOf(finalBytes)
	}
	return hashRes
}

func dim1HashWithGelement(
	commit mcl.G1,
	set []int,
	value_sub_vector []mcl.G1,
	n int) []mcl.Fr {
	setLen := len(set)
	if setLen != len(value_sub_vector) {
		fmt.Println("length of set and value_sub_vector does not match")
	}

	if setLen == 1 {
		frOne := make([]mcl.Fr, 1)
		frOne[0].SetInt64(1)
		return frOne
	}

	for _, eInSet := range set {
		if eInSet >= n {
			fmt.Println("Invalid Index")
		}
	}
	//tmp = c_i, \mathcal{C}(S_i), \bm{M}_i[\mathcal{C}(S_i)]
	tmp := make([]byte, 0)
	//add serialized commitment to tmp
	tmp = append(tmp, commit.Serialize()...)

	//add set to tmp
	for j := 0; j < setLen; j++ {
		tmp = append(tmp, IntToBytes(set[j])...)
	}

	//add set[i] to tmp
	for j := 0; j < setLen; j++ {
		if set[j] >= n {
			fmt.Println("Invalid Index in set")
		}
		tmp = append(tmp, value_sub_vector[j].Serialize()...)
	}

	hashRes := make([]mcl.Fr, setLen)
	for i := 0; i < setLen; i++ {
		finalBytes := append(IntToBytes(set[i]), tmp...)
		hashRes[i].SetHashOf(finalBytes)
	}
	return hashRes
}
