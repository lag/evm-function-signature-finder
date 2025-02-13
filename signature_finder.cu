// 4bytes/sigbrute.cu

#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include "keccak256.cuh"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>

// -----------------------------------------------------------------
// Definitions for streaming results
// -----------------------------------------------------------------
#define MAX_RECORD_SIZE 128    // Maximum bytes per result record.
#define MAX_HITS 1048576       // Maximum number of hit records.

// -----------------------------------------------------------------
// Device-side helper: write a result record.
// Writes the combined function string followed by a space and then the first 4 bytes of the hash (as hex),
// then a newline, and finally terminates (without extra padding).
// -----------------------------------------------------------------
__device__ inline void writeResultRecord(char* out, const char* combined, int combinedLen, const uint8_t* hash)
{
    int pos = 0;
    const char hexDigits[17] = "0123456789abcdef";
    // Append 4 bytes as 8 hex characters.
    for (int i = 0; i < 4; i++) {
        out[pos++] = hexDigits[hash[i] >> 4];
        out[pos++] = hexDigits[hash[i] & 0xF];
    }
    out[pos++] = ' ';  // Append a space.
    // Copy combined string.
    for (int i = 0; i < combinedLen; i++) {
        out[pos++] = combined[i];
    }
    out[pos++] = '\n'; // Append newline.
    out[pos] = '\0';   // Terminate.
}

// -----------------------------------------------------------------
// Device Kernel: bruteKernel
// -----------------------------------------------------------------
__global__ void bruteKernel(uint8_t* __restrict__ d_funcs, uint16_t maxFuncLength, int nFuncs,
                              uint8_t* __restrict__ d_args, uint16_t maxArgLength, int nArgs,
                              uint32_t* __restrict__ d_goals, int nGoals,
                              int* __restrict__ d_hitCounter, char* __restrict__ d_results)
{
    // 1 billion combinations
    const unsigned long long statusInterval = 1000000000ULL;
    unsigned long long totalComb = (unsigned long long)nFuncs * nArgs;
    unsigned long long totalThreads = blockDim.x * gridDim.x;
    unsigned long long gid = blockIdx.x * blockDim.x + threadIdx.x;
    int nArgsLocal = nArgs;

    // Process indices in strides of totalThreads.
    for (unsigned long long idx = gid; idx < totalComb; idx += totalThreads) {
        int funcIdx = idx / nArgsLocal;
        int argIdx  = idx % nArgsLocal;
        char* funcPtr = (char*)(d_funcs + funcIdx * maxFuncLength);
        char* argPtr  = (char*)(d_args + argIdx * maxArgLength);

        // Build combined string (assumes total length < 256).
        char combined[256];
        int combinedLen = 0;
        for (int i = 0; i < maxFuncLength; i++) {
            char c = funcPtr[i];
            if (c == '\0') break;
            combined[combinedLen++] = c;
        }
        for (int j = 0; j < maxArgLength; j++) {
            char c = argPtr[j];
            if (c == '\0') break;
            combined[combinedLen++] = c;
        }
        if (combinedLen < 256)
            combined[combinedLen] = '\0';

        if (idx % statusInterval == 0)
            printf("Status: Thread %llu processed combination index %llu\n", gid, idx);

        // Compute keccak256 hash.
        uint8_t hash[32];
        keccak256((uint8_t*)combined, combinedLen, hash);

        // Candidate is the first 4 bytes (big-endian).
        uint32_t candidate = ((uint32_t)hash[0] << 24) | ((uint32_t)hash[1] << 16) |
                             ((uint32_t)hash[2] << 8)  | ((uint32_t)hash[3]);
        int lo = 0, hi = nGoals - 1;
        bool found = false;
        // Binary search the sorted goal list.
        while (lo <= hi) {
            int mid = (lo + hi) / 2;
            uint32_t goal = __ldg(&d_goals[mid]);
            if (candidate == goal) { found = true; break; }
            else if (candidate < goal) hi = mid - 1;
            else lo = mid + 1;
        }
        if (found) {
            int slot = atomicAdd(d_hitCounter, 1);
            if (slot < MAX_HITS) {
                printf("Found match: %08x | %s\n", candidate, combined);
                writeResultRecord(&d_results[slot * MAX_RECORD_SIZE], combined, combinedLen, hash);
            }
        }
    }
}

// -----------------------------------------------------------------
// Host Helper Functions
// -----------------------------------------------------------------
std::vector<std::string> load_words(const char* filename, uint16_t maxLength)
{
    std::vector<std::string> words;
    std::ifstream file(filename);
    if (!file.good()) {
        std::cerr << "Failed to open " << filename << std::endl;
        return words;
    }
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (line.size() > maxLength)
            line = line.substr(0, maxLength);
        words.push_back(line);
    }
    return words;
}

std::vector<uint32_t> load_goals(const char* filename)
{
    std::vector<uint32_t> goals;
    std::ifstream file(filename);
    if (!file.good()) {
        std::cerr << "Failed to open " << filename << std::endl;
        return goals;
    }
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            uint32_t val = (uint32_t)strtoul(line.c_str(), NULL, 16);
            goals.push_back(val);
        }
    }
    return goals;
}

// -----------------------------------------------------------------
// Main
// -----------------------------------------------------------------
int main(int argc, char** argv)
{
    if (argc < 7) {
        printf("Usage: %s --funclength <maxFuncLength> --arglength <maxArgLength> --funcs <funcsFile> --args <argsFile> --signatures <signaturesFile>\n", argv[0]);
        return 1;
    }
    uint16_t maxFuncLength = 0, maxArgLength = 0;
    char* funcsFile = "funcs.txt", *argsFile = "args.txt", *signaturesFile = "signatures.txt";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--funclength") == 0 && i + 1 < argc) {
            maxFuncLength = (uint16_t)atoi(argv[i + 1]);
            i++;
        }
        else if (strcmp(argv[i], "--arglength") == 0 && i + 1 < argc) {
            maxArgLength = (uint16_t)atoi(argv[i + 1]);
            i++;
        }
        else if (strcmp(argv[i], "--funcs") == 0 && i + 1 < argc) {
            funcsFile = argv[i + 1];
            i++;
        }
        else if (strcmp(argv[i], "--args") == 0 && i + 1 < argc) {
            argsFile = argv[i + 1];
            i++;
        }
        else if (strcmp(argv[i], "--signatures") == 0 && i + 1 < argc) {
            signaturesFile = argv[i + 1];
            i++;
        }
    }

    // Load function and argument words.
    std::vector<std::string> funcs = load_words(funcsFile, maxFuncLength);
    std::vector<std::string> args  = load_words(argsFile, maxArgLength);
    if (funcs.empty() || args.empty()) {
        printf("Error: Unable to load words from %s or %s\n", funcsFile, argsFile);
        return 1;
    }
    int nFuncs = funcs.size();
    int nArgs  = args.size();
    printf("Loaded %d function words and %d argument words.\n", nFuncs, nArgs);

    // Load goal signatures.
    std::vector<uint32_t> goals = load_goals(signaturesFile);
    if (goals.empty()) {
        printf("Error: No goal signatures loaded from %s\n", signaturesFile);
        return 1;
    }
    int nGoals = goals.size();
    printf("Loaded %d goal signatures.\n", nGoals);

    // Pack words into contiguous fixed-width host arrays.
    char* h_funcs = (char*)malloc(nFuncs * maxFuncLength);
    char* h_args  = (char*)malloc(nArgs * maxArgLength);
    memset(h_funcs, 0, nFuncs * maxFuncLength);
    memset(h_args, 0, nArgs * maxArgLength);
    for (int i = 0; i < nFuncs; i++) {
        strncpy(h_funcs + i * maxFuncLength, funcs[i].c_str(), maxFuncLength - 1);
    }
    for (int i = 0; i < nArgs; i++) {
        strncpy(h_args + i * maxArgLength, args[i].c_str(), maxArgLength - 1);
    }
    
    uint32_t* h_goals = (uint32_t*)malloc(nGoals * sizeof(uint32_t));
    for (int i = 0; i < nGoals; i++) {
        h_goals[i] = goals[i];
    }
    
    // Allocate device memory.
    char* d_funcs;
    char* d_args;
    uint32_t* d_goals;
    cudaMalloc((void**)&d_funcs, nFuncs * maxFuncLength);
    cudaMalloc((void**)&d_args, nArgs * maxArgLength);
    cudaMalloc((void**)&d_goals, nGoals * sizeof(uint32_t));
    cudaMemcpy(d_funcs, h_funcs, nFuncs * maxFuncLength, cudaMemcpyHostToDevice);
    cudaMemcpy(d_args, h_args, nArgs * maxArgLength, cudaMemcpyHostToDevice);
    cudaMemcpy(d_goals, h_goals, nGoals * sizeof(uint32_t), cudaMemcpyHostToDevice);

    // Allocate device memory for the hit counter and results.
    int* d_hitCounter;
    char* d_results;
    cudaMalloc((void**)&d_hitCounter, sizeof(int));
    cudaMalloc((void**)&d_results, MAX_HITS * MAX_RECORD_SIZE);
    cudaMemset(d_hitCounter, 0, sizeof(int));

    unsigned long long totalComb = (unsigned long long)nFuncs * nArgs;
    printf("Total combinations: %llu\n", totalComb);

    // Create a CUDA stream and launch the kernel.
    cudaStream_t stream;
    cudaStreamCreate(&stream);
    dim3 grid(256), block(256);
    bruteKernel<<<grid, block, 0, stream>>>((uint8_t*)d_funcs, maxFuncLength, nFuncs,
                                             (uint8_t*)d_args, maxArgLength, nArgs,
                                             d_goals, nGoals, d_hitCounter, d_results);
    
    // Open the output file (append mode).
    FILE* f = fopen("resolved.txt", "a");
    if (!f) {
        fprintf(stderr, "Failed to open resolved.txt for appending.\n");
        return 1;
    }
    setvbuf(f, NULL, _IONBF, 0);

    // Poll the hit counter and copy new results to host then file.
    int lastCount = 0;
    // Final check after kernel completion.
    int count;
    cudaMemcpy(&count, d_hitCounter, sizeof(int), cudaMemcpyDeviceToHost);
    if (count > lastCount) {
        int newCount = count - lastCount;
        char* h_buffer = (char*)malloc(newCount * MAX_RECORD_SIZE);
        cudaMemcpy(h_buffer, d_results + lastCount * MAX_RECORD_SIZE, newCount * MAX_RECORD_SIZE, cudaMemcpyDeviceToHost);
        for (int i = 0; i < newCount; i++) {
            char* record = h_buffer + i * MAX_RECORD_SIZE;
            size_t len = strlen(record);
            fwrite(record, 1, len, f);
        }
        fflush(f);
        free(h_buffer);
    }
    fclose(f);
    cudaStreamDestroy(stream);

    // Clean up.
    cudaFree(d_funcs);
    cudaFree(d_args);
    cudaFree(d_goals);
    cudaFree(d_hitCounter);
    cudaFree(d_results);
    free(h_funcs);
    free(h_args);
    free(h_goals);

    return 0;
}