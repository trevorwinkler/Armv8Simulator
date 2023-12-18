/*
* File: team4_project2.go
* CS 3339.001: Team 4
* Authors: Jacob Doney, Jordan Burgess, Trevor Winkler
* Last Update: 11/30/2023
*
* Description: LegV8 disassembler to convert machine code back
* into LEGv8 Assembly Language. This disassembler takes in a 32 bit binary
* machine code file, processes it, and outputs a text file containing the
* disassembled code as well as a simulation text file showing the state of each register
* and memory address for each instruction.
 */

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
)

type Instruction struct {
	binaryStr   string
	opcode      string
	format      string
	disassembly string
	memory      int
	rm          uint32
	shamt       uint32
	rn          uint32
	rd          uint32
	address     uint32
	rt          uint32
	offset      int32
	immediate   uint32
	conditional uint32
	shift       uint32
	field       uint32
}

type Data struct {
	value  int32
	memory int32
	binary string
}

// stringToUint32 converts a binary string to a 32-bit unsigned integer.
func stringToUint32(binaryStr string) uint32 {
	intValue, err := strconv.ParseUint(binaryStr, 2, 64)
	if err != nil {
		log.Fatalf("Failed parsing Uint %s", err)
	}
	return uint32(intValue)
}

// stringToInt32 converts a binary string to a 32-bit signed integer.
func stringToInt32(binaryStr string) int32 {

	// Appending string of 1s to front negative values to make 32 bits
	if binaryStr[0] == '1' {
		for len(binaryStr) < 32 {
			binaryStr = "1" + binaryStr
		}
	}

	intValue, err := strconv.ParseInt(binaryStr, 2, 64)
	if err != nil {
		log.Fatalf("Failed parsing Int %s", err)
	}
	return int32(intValue)
}

// isValidBinary checks if a string is a valid 32-bit binary string.
func isValidBinary(binaryStr string) bool {
	if len(binaryStr) != 32 {
		return false
	}
	for i := 0; i < len(binaryStr); i++ {
		if binaryStr[i] != '1' && binaryStr[i] != '0' {
			return false
		}
	}
	return true
}

// getOPCODE determines the opcode and instruction format for a given LEGv8 binary instruction.
func getOPCODE(opcode uint32) (string, string) {
	var opStr string
	var format string
	if opcode >= 160 && opcode <= 191 {
		opStr = "B"
		format = "B"
	} else if opcode == 1104 {
		opStr = "AND"
		format = "R"
	} else if opcode == 1112 {
		opStr = "ADD"
		format = "R"
	} else if opcode >= 1160 && opcode <= 1161 {
		opStr = "ADDI"
		format = "I"
	} else if opcode == 1360 {
		opStr = "ORR"
		format = "R"
	} else if opcode >= 1440 && opcode <= 1447 {
		opStr = "CBZ"
		format = "CB"
	} else if opcode >= 1448 && opcode <= 1455 {
		opStr = "CBNZ"
		format = "CB"
	} else if opcode == 1624 {
		opStr = "SUB"
		format = "R"
	} else if opcode >= 1672 && opcode <= 1673 {
		opStr = "SUBI"
		format = "I"
	} else if opcode >= 1684 && opcode <= 1687 {
		opStr = "MOVZ"
		format = "IM"
	} else if opcode >= 1940 && opcode <= 1943 {
		opStr = "MOVK"
		format = "IM"
	} else if opcode == 1690 {
		opStr = "LSR"
		format = "R"
	} else if opcode == 1691 {
		opStr = "LSL"
		format = "R"
	} else if opcode == 1984 {
		opStr = "STUR"
		format = "D"
	} else if opcode == 1986 {
		opStr = "LDUR"
		format = "D"
	} else if opcode == 1692 {
		opStr = "ASR"
		format = "R"
	} else if opcode == 0 {
		opStr = "NOP"
		format = "N/A"
	} else if opcode == 1872 {
		opStr = "EOR"
		format = "R"
	} else if opcode == 2038 {
		opStr = "BREAK"
		format = "BREAK"
	} else {
		opStr = "Unknown Instruction"
		format = "Other"
	}
	return opStr, format
}

// getInstruction Creates and returns an Instruction struct
// Returns true if instruction code is break
func getInstruction(binaryStr string) (bool, Instruction) {
	opcode, format := getOPCODE(stringToUint32(binaryStr[:11]))
	dataFlag := false
	instruction := Instruction{}
	switch format {
	case "BREAK":
		dataFlag = true
		instruction = Instruction{binaryStr: binaryStr, opcode: opcode, format: format}
	case "R":
		binary := stringToUint32(binaryStr)
		rm := (binary >> 0x10) & 0x1F
		shamt := (binary >> 0xA) & 0x3F
		rn := (binary >> 0x5) & 0x1F
		rd := binary & 0x1F
		instruction = Instruction{rm: rm, shamt: shamt, rn: rn, rd: rd,
			binaryStr: binaryStr, opcode: opcode, format: format}
	case "D":
		binary := stringToUint32(binaryStr)
		address := (binary >> 0xC) & 0x1FF
		rn := (binary >> 0x5) & 0x1F
		rt := binary & 0x1F
		instruction = Instruction{address: address, rn: rn, rt: rt,
			binaryStr: binaryStr, opcode: opcode, format: format}
	case "I":
		binary := stringToUint32(binaryStr)
		immediate := (binary >> 10) & 0xFFF
		rn := (binary >> 0x5) & 0x1F
		rd := binary & 0x1F
		instruction = Instruction{rd: rd, rn: rn, immediate: immediate,
			binaryStr: binaryStr, opcode: opcode, format: format}
	case "CB":
		binary := stringToUint32(binaryStr)
		conditional := binary & 0x1F
		offset := stringToInt32(binaryStr[8:27])
		instruction = Instruction{conditional: conditional, offset: offset,
			binaryStr: binaryStr, opcode: opcode, format: format}
	case "B":
		offset := stringToInt32(binaryStr[6:])
		instruction = Instruction{offset: offset, binaryStr: binaryStr, opcode: opcode, format: format}
	case "IM":
		binary := stringToUint32(binaryStr)
		shift := 16 * ((binary >> 21) & 0x3)
		field := (binary >> 5) & 0xFFFF
		rd := binary & 0x1F
		instruction = Instruction{shift: shift, field: field, rd: rd, binaryStr: binaryStr, opcode: opcode, format: format}
	default:
		instruction = Instruction{binaryStr: binaryStr, opcode: opcode, format: format}
	}
	return dataFlag, instruction
}

// getFileData reads the input file and stores the instructions in a list and the data into a list
func getFileData(inputFile string) ([]Instruction, []Data) {
	fileIn, err := os.Open(inputFile)
	if err != nil {
		log.Fatalf("Failed opening file %s", err)
	}
	scanner := bufio.NewScanner(fileIn)
	scanner.Split(bufio.ScanLines)
	var instructionList []Instruction
	var dataList []Data
	var eachline string
	isData := false
	instructionInfo := Instruction{}
	data := Data{}

	for scanner.Scan() {
		eachline = scanner.Text()
		eachline = strings.TrimSuffix(eachline, "\n")
		eachline = strings.Trim(eachline, " ")
		eachline = strings.Replace(eachline, " ", "", -1)
		if isValidBinary(eachline) {
			if !isData {
				isData, instructionInfo = getInstruction(eachline)
				instructionList = append(instructionList, instructionInfo)
			} else {
				data = Data{value: stringToInt32(eachline), binary: eachline}
				dataList = append(dataList, data)
			}
		} else {
			badInstruction := Instruction{binaryStr: eachline, opcode: "Unknown Instruction", format: "Other"}
			instructionList = append(instructionList, badInstruction)
		}
	}

	err = fileIn.Close()
	if err != nil {
		log.Fatalf("Failed closing file %s", err)
	}
	return instructionList, dataList
}

// createOutputFile creates the output file with the disassembled LEGv8 assembly code.
func outputDisassemble(outputFile string, instructions []Instruction, datalist []Data) {

	var toPrint = ""
	memory := 96

	fileOut, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("Failed creating output file %s", err)
	}

	for i, instruction := range instructions {
		switch instruction.format {
		case "BREAK":
			toPrint = fmt.Sprintf("%1s %5s %5s %5s %5s %5s %6s\t%d\t%s\n",
				instruction.binaryStr[:1], instruction.binaryStr[1:6], instruction.binaryStr[6:11],
				instruction.binaryStr[11:16], instruction.binaryStr[16:21],
				instruction.binaryStr[21:26], instruction.binaryStr[26:], memory, instruction.opcode)
			instructions[i].disassembly = fmt.Sprintf("%s\n", instruction.opcode)
		case "R":
			if instruction.opcode == "LSR" || instruction.opcode == "LSL" || instruction.opcode == "ASR" {
				toPrint = fmt.Sprintf("%11s %5s %6s %5s %5s\t%d\t%s\tR%d, R%d, #%d\n",
					instruction.binaryStr[:11], instruction.binaryStr[11:16], instruction.binaryStr[16:22],
					instruction.binaryStr[22:27], instruction.binaryStr[27:],
					memory, instruction.opcode, instruction.rd, instruction.rn, instruction.shamt)
				instructions[i].disassembly = fmt.Sprintf("%s\tR%d, R%d, #%d\n", instruction.opcode, instruction.rd, instruction.rn, instruction.shamt)
			} else {
				toPrint = fmt.Sprintf("%11s %5s %6s %5s %5s\t%d\t%s\tR%d, R%d, R%d\n",
					instruction.binaryStr[:11], instruction.binaryStr[11:16], instruction.binaryStr[16:22],
					instruction.binaryStr[22:27], instruction.binaryStr[27:],
					memory, instruction.opcode, instruction.rd, instruction.rn, instruction.rm)
				instructions[i].disassembly = fmt.Sprintf("%s\tR%d, R%d, R%d\n", instruction.opcode, instruction.rd, instruction.rn, instruction.rm)
			}
		case "D":
			toPrint = fmt.Sprintf("%11s %9s %2s %5s %5s\t%d\t%s\tR%d, [R%d, #%d]\n",
				instruction.binaryStr[:11], instruction.binaryStr[11:20], instruction.binaryStr[20:22],
				instruction.binaryStr[22:27], instruction.binaryStr[27:],
				memory, instruction.opcode, instruction.rt, instruction.rn, instruction.address)
			instructions[i].disassembly = fmt.Sprintf("%s\tR%d, [R%d, #%d]\n", instruction.opcode, instruction.rt, instruction.rn, instruction.address)
		case "I":
			toPrint = fmt.Sprintf("%10s %12s %5s %5s\t%d\t%s\tR%d, R%d, #%d\n",
				instruction.binaryStr[:10], instruction.binaryStr[10:22], instruction.binaryStr[22:27], instruction.binaryStr[27:],
				memory, instruction.opcode, instruction.rd, instruction.rn, instruction.immediate)
			instructions[i].disassembly = fmt.Sprintf("%s\tR%d, R%d, #%d\n", instruction.opcode, instruction.rd, instruction.rn, instruction.immediate)
		case "CB":
			toPrint = fmt.Sprintf("%8s %19s %5s\t%d\t%s\tR%d, #%d\n",
				instruction.binaryStr[:8], instruction.binaryStr[8:27], instruction.binaryStr[27:],
				memory, instruction.opcode, instruction.conditional, instruction.offset)
			instructions[i].disassembly = fmt.Sprintf("%s\tR%d, #%d\n", instruction.opcode, instruction.conditional, instruction.offset)
		case "B":
			toPrint = fmt.Sprintf("%6s %26s\t%d\t%s\t#%d\n",
				instruction.binaryStr[:6], instruction.binaryStr[6:], memory, instruction.opcode, instruction.offset)
			instructions[i].disassembly = fmt.Sprintf("%s\t#%d\n", instruction.opcode, instruction.offset)
		case "IM":
			toPrint = fmt.Sprintf("%9s %2s %16s %5s\t%d\t%s\tR%d, %d, LSL %d\n",
				instruction.binaryStr[:9], instruction.binaryStr[9:11], instruction.binaryStr[11:27], instruction.binaryStr[27:],
				memory, instruction.opcode, instruction.rd, instruction.field, instruction.shift)
			instructions[i].disassembly = fmt.Sprintf("%s\tR%d, %d, LSL %d\n", instruction.opcode, instruction.rd, instruction.field, instruction.shift)
		case "N/A":
			toPrint = fmt.Sprintf("%32s\t%d\t%s\n", instruction.binaryStr, memory, instruction.opcode)
			instructions[i].disassembly = fmt.Sprintf("%s\n", instruction.opcode)
		default:
			toPrint = fmt.Sprintf("%s\t%s\n", instruction.binaryStr, instruction.opcode)
			instructions[i].disassembly = fmt.Sprintf("%s\n", instruction.opcode)
		}
		if instruction.opcode != "Unknown Instruction" {
			instructions[i].memory = memory
			memory += 4
		}
		_, err := fileOut.WriteString(toPrint)
		if err != nil {
			log.Fatalf("Failed Writing to file %s", err)
		}
	}
	for i, data := range datalist {
		toPrint = fmt.Sprintf("%32s\t%d\t%d\n", data.binary, memory, data.value)
		datalist[i].memory = int32(memory)
		memory += 4
		_, err := fileOut.WriteString(toPrint)
		if err != nil {
			log.Fatalf("Failed Writing to file %s", err)
		}
	}

	err = fileOut.Close()
	if err != nil {
		log.Fatalf("Failed closing output file %s", err)
	}

}

// updateRegisters updates registers based on instruction code
func updateRegisters(instruction Instruction, register *[32]int32) {
	switch instruction.opcode {
	case "SUB":
		register[instruction.rd] = register[instruction.rn] - register[instruction.rm]
	case "ADD":
		register[instruction.rd] = register[instruction.rn] + register[instruction.rm]
	case "AND":
		register[instruction.rd] = register[instruction.rn] & register[instruction.rm]
	case "ORR":
		register[instruction.rd] = register[instruction.rn] | register[instruction.rm]
	case "EOR":
		register[instruction.rd] = register[instruction.rn] ^ register[instruction.rm]
	case "ADDI":
		register[instruction.rd] = register[instruction.rn] + int32(instruction.immediate)
	case "SUBI":
		register[instruction.rd] = register[instruction.rn] - int32(instruction.immediate)
	case "LSL":
		register[instruction.rd] = register[instruction.rn] << instruction.shamt
	case "ASR":
		if register[instruction.rn] < 0 {
			mask := int32(-1) << (32 - instruction.shamt)
			register[instruction.rd] = (register[instruction.rn] >> instruction.shamt) | mask
		} else {
			register[instruction.rd] = register[instruction.rn] >> instruction.shamt
		}
	case "LSR":
		if register[instruction.rn] < 0 {
			register[instruction.rd] = int32(uint32(register[instruction.rn]) >> instruction.shamt)
		} else {
			register[instruction.rd] = register[instruction.rn] >> instruction.shamt
		}
	case "MOVZ":
		register[instruction.rd] = int32(instruction.field << instruction.shift)
	case "MOVK":
		register[instruction.rd] &= ^(0xFFF << (instruction.shift))
		register[instruction.rd] |= int32(instruction.field << instruction.shift)
	}
}

// setUpMemory creates memory information based on initial input information
func setUpMemory(dataList []Data) map[int32][8]int8 {
	memoryBlocks := 8
	wordSize := 4
	addressSize := 32
	var memory map[int32][8]int8
	memory = make(map[int32][8]int8)
	placed := false
	for _, data := range dataList {
		address := data.memory
		place := (address % int32(addressSize)) / int32(wordSize)
		if len(memory) == 0 {
			memory[address] = [8]int8{}
			memorySpace := memory[address]
			memorySpace[0] = int8(data.value)
			memory[address] = memorySpace
		} else {
			for key := range memory {
				if address < key+32 {
					place = place - (key%int32(addressSize))/int32(wordSize)
					if place < 0 {
						place = int32(memoryBlocks) + place
					}
					memorySpace := memory[key]
					memorySpace[place] = int8(data.value)
					memory[key] = memorySpace
					placed = true
				}
			}
		}
		if placed == false {
			memory[address] = [8]int8{}
			memorySpace := memory[address]
			memorySpace[0] = int8(data.value)
			memory[address] = memorySpace
		} else {
			placed = false
		}
	}
	return memory
}

// outputSim creates the _sim.txt file
func outputSim(outputFile string, instructions []Instruction, dataList []Data) {
	cycle := 0
	var registers [32]int32
	var memory map[int32][8]int8
	memory = make(map[int32][8]int8)
	toPrint := ""

	fileOut, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("Failed creating output file %s", err)
	}
	last := len(instructions) - 1
	maxMemory := int32(instructions[last].memory)
	if len(dataList) > 0 {
		memory = setUpMemory(dataList)
	}

	i := 0
	for i < len(instructions) {
		if instructions[i].opcode != "Unknown Instruction" {
			toPrint = fmt.Sprintf("====================\n")
			toPrint += fmt.Sprintf("cycle:%d\t%d\t%s", cycle+1, instructions[i].memory, instructions[i].disassembly)
			if instructions[i].format == "R" || instructions[i].format == "I" || instructions[i].format == "IM" {
				updateRegisters(instructions[i], &registers)
			}
			if instructions[i].opcode == "STUR" || instructions[i].opcode == "LDUR" {
				memory, registers = handleMemory(memory, instructions[i], registers, maxMemory)
			}

			toPrint += fmt.Sprintf("\nregisters:\n")
			toPrint += fmt.Sprintf("r00:\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", registers[0], registers[1],
				registers[2], registers[3], registers[4], registers[5], registers[6], registers[7])
			toPrint += fmt.Sprintf("r08:\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", registers[8], registers[9],
				registers[10], registers[11], registers[12], registers[13], registers[14], registers[15])
			toPrint += fmt.Sprintf("r16:\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", registers[16], registers[17],
				registers[18], registers[19], registers[20], registers[21], registers[22], registers[23])
			toPrint += fmt.Sprintf("r24:\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n\n", registers[24], registers[27],
				registers[26], registers[27], registers[28], registers[29], registers[30], registers[31])
			toPrint += fmt.Sprintf("data:\n")

			if memory != nil {
				var keys []int32
				for k := range memory {
					keys = append(keys, k)
				}
				sort.Slice(keys, func(i, j int) bool {
					return keys[i] < keys[j]
				})
				for _, key := range keys {
					value := memory[key]
					toPrint += fmt.Sprintf("%d:\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", key, value[0], value[1],
						value[2], value[3], value[4], value[5], value[6], value[7])
				}
			}
			_, err := fileOut.WriteString(toPrint)
			if err != nil {
				log.Fatalf("Failed Writing to file %s", err)
			}

			// Handling branching
			if instructions[i].format == "B" {
				// Check to see if we branch out of bounds
				if i+int(instructions[i].offset) >= len(instructions) || i+int(instructions[i].offset) < 0 {
					i = len(instructions)
					log.Fatalf("Branch instruction out of bounds")
				} else {
					// update index based on the offset value
					i = i + int(instructions[i].offset)
				}
			} else if instructions[i].format == "CB" {
				if instructions[i].opcode == "CBNZ" {
					// If the register is NOT a zero we branch
					if registers[instructions[i].conditional] != 0 {
						// Check to see if we branch out of bounds
						if i+int(instructions[i].offset) >= len(instructions) || i+int(instructions[i].offset) < 0 {
							i = len(instructions)
							log.Fatalf("Branch instruction out of bounds")
						} else {
							i = i + int(instructions[i].offset)
						}
					} else {
						i++
					}
				} else {
					// If the register is zero we branch
					if registers[instructions[i].conditional] == 0 {
						// Check to see if we branch out of bounds
						if i+int(instructions[i].offset) >= len(instructions) || i+int(instructions[i].offset) < 0 {
							i = len(instructions)
							log.Fatalf("Branch instruction out of bounds")
						} else {
							i = i + int(instructions[i].offset)
						}
					} else {
						i++
					}
				}
			} else {
				i++ // If we don't branch go to next instruction
			}
			cycle++
		}
		toPrint = ""
	}
}

func handleMemory(memory map[int32][8]int8, instruction Instruction, registers [32]int32, maxKey int32) (map[int32][8]int8, [32]int32) {
	memoryBlocks := 8
	wordSize := 4
	addressSize := 32
	if instruction.opcode == "STUR" {
		key := registers[instruction.rn] + int32(instruction.address*4)
		adr := 0
		placed := false
		for adr < memoryBlocks {
			tempKey := key - int32(adr*wordSize)
			_, exists := memory[tempKey]
			if exists {
				place := ((key % int32(addressSize)) / int32(wordSize)) - ((tempKey % int32(addressSize)) / int32(wordSize))
				if place < 0 {
					place = int32(memoryBlocks) + place
				}
				memorySpace := memory[tempKey]
				memorySpace[place] = int8(registers[instruction.rt])
				memory[tempKey] = memorySpace
				placed = true
				break
			}
			adr++
		}
		// If data segment does not already exist
		if placed == false {
			for keyVal := range memory {
				if keyVal > maxKey {
					maxKey = keyVal
				}
			}
			makeKey := maxKey
			if len(memory) == 0 {
				makeKey = makeKey + 4
			} else {
				makeKey = makeKey + int32(addressSize)
			}
			if key >= maxKey+32 {
				// creating data lines
				for key >= makeKey {
					memory[makeKey] = [8]int8{}
					makeKey = makeKey + int32(addressSize)
				}
				makeKey = makeKey - int32(addressSize)

			}
			memorySpace := memory[makeKey]
			// Find the correct place to insert data
			place := ((key % int32(addressSize)) / int32(wordSize)) - ((makeKey % int32(addressSize)) / int32(wordSize))
			if place < 0 {
				place = int32(memoryBlocks) + place
			}
			memorySpace[place] = int8(registers[instruction.rt])
			memory[makeKey] = memorySpace
		}
	}
	if instruction.opcode == "LDUR" {
		key := int32(instruction.address*uint32(wordSize)) + registers[instruction.rn]
		adr := 0
		updated := false
		for adr < memoryBlocks {
			tempKey := key - int32(adr*wordSize)
			_, exists := memory[tempKey]
			if exists {
				//find the correct index to retrieve the new data
				place := ((key % int32(addressSize)) / int32(wordSize)) - ((tempKey % int32(addressSize)) / int32(wordSize))
				if place < 0 {
					place = int32(memoryBlocks) + place
				}
				registers[instruction.rt] = int32(memory[tempKey][place])
				updated = true
				break
			}
			adr++
		}
		// if out of range fill register with 0
		if updated == false {
			registers[instruction.rt] = int32(0)
		}
	}
	return memory, registers
}

// main handles the flags and runs the disassembler
func main() {
	var InputFileName *string
	var OutputFileName *string

	var DisFileExtension = "_dis.txt"
	var SimFileExtension = "_sim.txt"

	InputFileName = flag.String("i", "", "Gets the input file name")
	OutputFileName = flag.String("o", "", "Gets the output file name")

	flag.Parse()

	// To fix the issue if compiled with go run . team4_project2.go -i <input file> -o <output file>
	// The . is preventing the flag.Sting() functions from working
	if flag.NArg() != 0 {
		for i := 0; i < flag.NArg(); i++ {
			if flag.Arg(i) == "-i" && i+1 <= flag.NArg() {
				*InputFileName = flag.Arg(i + 1)
			}
			if flag.Arg(i) == "-o" && i+1 <= flag.NArg() {
				*OutputFileName = flag.Arg(i + 1)
			}
		}
	}

	if *InputFileName == "" || *OutputFileName == "" {
		fmt.Println("Input and output file names are required.")
		flag.Usage()
		os.Exit(1)
	}
	instructionList, dataList := getFileData(*InputFileName)
	outputDisassemble(*OutputFileName+DisFileExtension, instructionList, dataList)
	outputSim(*OutputFileName+SimFileExtension, instructionList, dataList)
}
