/*
 * Copyright 2009 Colin Percival, 2011 ArtForz
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

#define __STDC_LIMIT_MACROS

#include "scrypt.h"
#include <stdlib.h>


#include <stdint.h>

#include "uint256.h"
#include "bignum.h"
#include "hash.h"

#include <string.h>
#include <openssl/sha.h>
#include <errno.h>

static void blkcpy(uint8_t *, uint8_t *, size_t);
static void blkxor(uint8_t *, uint8_t *, size_t);
static void salsa20_8(uint8_t[64]);
static void blockmix_salsa8(uint8_t *, uint8_t *, size_t);
static uint64_t integerify(uint8_t *, size_t);
static void smix(uint8_t *, size_t, uint64_t, uint8_t *, uint8_t *);



static double dataFinal [][4] = {
{ 16 , 6 , 9 , 1.306 },
{ 8 , 11 , 10 , 1.325 },
{ 8 , 10 , 11 , 1.33 },
{ 16 , 5 , 11 , 1.336 },
{ 16 , 11 , 5 , 1.338 },
{ 32 , 9 , 3 , 1.338 },
{ 32 , 3 , 9 , 1.341 },
{ 8 , 8 , 14 , 1.354 },
{ 16 , 7 , 8 , 1.355 },
{ 4 , 15 , 15 , 1.356 },
{ 8 , 14 , 8 , 1.356 },
{ 16 , 4 , 14 , 1.366 },
{ 16 , 8 , 7 , 1.371 },
{ 32 , 7 , 4 , 1.374 },
{ 64 , 1 , 12 , 1.379 },
{ 16 , 14 , 4 , 1.38 },
{ 32 , 4 , 7 , 1.38 },
{ 32 , 14 , 2 , 1.384 },
{ 64 , 7 , 2 , 1.387 },
{ 128 , 7 , 1 , 1.392 },
{ 32 , 2 , 14 , 1.41 },
{ 64 , 2 , 7 , 1.416 },
{ 8 , 13 , 9 , 1.42 },
{ 8 , 9 , 13 , 1.433 },
{ 8 , 12 , 10 , 1.446 },
{ 8 , 8 , 15 , 1.448 },
{ 64 , 14 , 1 , 1.453 },
{ 16 , 5 , 12 , 1.456 },
{ 16 , 10 , 6 , 1.456 },
{ 8 , 15 , 8 , 1.457 },
{ 16 , 15 , 4 , 1.462 },
{ 64 , 15 , 1 , 1.462 },
{ 16 , 12 , 5 , 1.463 },
{ 128 , 1 , 7 , 1.463 },
{ 16 , 4 , 15 , 1.466 },
{ 32 , 6 , 5 , 1.467 },
{ 32 , 10 , 3 , 1.47 },
{ 32 , 15 , 2 , 1.47 },
{ 8 , 10 , 12 , 1.471 },
{ 32 , 5 , 6 , 1.474 },
{ 8 , 11 , 11 , 1.477 },
{ 16 , 6 , 10 , 1.48 },
{ 32 , 3 , 10 , 1.481 },
{ 64 , 3 , 5 , 1.492 },
{ 32 , 2 , 15 , 1.499 },
{ 64 , 1 , 13 , 1.513 },
{ 8 , 14 , 9 , 1.518 },
{ 8 , 9 , 14 , 1.523 },
{ 16 , 9 , 7 , 1.524 },
{ 16 , 7 , 9 , 1.529 },
{ 64 , 5 , 3 , 1.542 },
{ 16 , 8 , 8 , 1.547 },
{ 8 , 13 , 10 , 1.565 },
{ 128 , 8 , 1 , 1.57 },
{ 8 , 10 , 13 , 1.572 },
{ 32 , 8 , 4 , 1.575 },
{ 16 , 13 , 5 , 1.576 },
{ 32 , 4 , 8 , 1.576 },
{ 8 , 12 , 11 , 1.589 },
{ 64 , 4 , 4 , 1.597 },
{ 16 , 6 , 11 , 1.6 },
{ 128 , 4 , 2 , 1.602 },
{ 16 , 11 , 6 , 1.61 },
{ 64 , 2 , 8 , 1.612 },
{ 32 , 11 , 3 , 1.615 },
{ 8 , 11 , 12 , 1.617 },
{ 64 , 8 , 2 , 1.621 },
{ 8 , 9 , 15 , 1.63 },
{ 32 , 3 , 11 , 1.631 },
{ 16 , 5 , 13 , 1.633 },
{ 8 , 15 , 9 , 1.637 },
{ 128 , 2 , 4 , 1.679 },
{ 8 , 14 , 10 , 1.688 },
{ 64 , 1 , 14 , 1.689 },
{ 16 , 7 , 10 , 1.69 },
{ 8 , 10 , 14 , 1.693 },
{ 16 , 10 , 7 , 1.697 },
{ 128 , 1 , 8 , 1.697 },
{ 16 , 14 , 5 , 1.703 },
{ 32 , 7 , 5 , 1.704 },
{ 16 , 5 , 14 , 1.706 },
{ 32 , 5 , 7 , 1.708 },
{ 8 , 11 , 13 , 1.724 },
{ 8 , 12 , 12 , 1.735 },
{ 16 , 9 , 8 , 1.739 },
{ 16 , 12 , 6 , 1.74 },
{ 8 , 13 , 11 , 1.741 },
{ 16 , 6 , 12 , 1.742 },
{ 16 , 8 , 9 , 1.742 },
{ 64 , 1 , 15 , 1.75 },
{ 32 , 9 , 4 , 1.753 },
{ 64 , 9 , 2 , 1.757 },
{ 32 , 6 , 6 , 1.759 },
{ 32 , 4 , 9 , 1.766 },
{ 64 , 6 , 3 , 1.78 },
{ 32 , 12 , 3 , 1.802 },
{ 128 , 3 , 3 , 1.806 },
{ 8 , 15 , 10 , 1.82 },
{ 64 , 3 , 6 , 1.82 },
{ 16 , 5 , 15 , 1.822 },
{ 64 , 2 , 9 , 1.822 },
{ 16 , 15 , 5 , 1.84 },
{ 8 , 10 , 15 , 1.844 },
{ 8 , 14 , 11 , 1.851 },
{ 16 , 7 , 11 , 1.856 },
{ 16 , 11 , 7 , 1.872 },
{ 8 , 13 , 12 , 1.873 },
{ 8 , 12 , 13 , 1.879 },
{ 8 , 11 , 14 , 1.884 },
{ 16 , 6 , 13 , 1.891 },
{ 32 , 3 , 12 , 1.896 },
{ 16 , 13 , 6 , 1.901 },
{ 128 , 1 , 9 , 1.903 },
{ 32 , 13 , 3 , 1.921 },
{ 16 , 8 , 10 , 1.933 },
{ 16 , 10 , 8 , 1.944 },
{ 64 , 10 , 2 , 1.95 },
{ 32 , 8 , 5 , 1.952 },
{ 16 , 9 , 9 , 1.954 },
{ 32 , 4 , 10 , 1.959 },
{ 32 , 10 , 4 , 1.96 },
{ 32 , 5 , 8 , 1.966 },
{ 64 , 5 , 4 , 1.971 },
{ 64 , 4 , 5 , 1.981 },
{ 8 , 15 , 11 , 2.013 },
{ 128 , 5 , 2 , 2.014 },
{ 8 , 11 , 15 , 2.021 },
{ 8 , 12 , 14 , 2.021 },
{ 64 , 2 , 10 , 2.023 },
{ 16 , 7 , 12 , 2.028 },
{ 8 , 13 , 13 , 2.034 },
{ 8 , 14 , 12 , 2.044 },
{ 32 , 7 , 6 , 2.049 },
{ 16 , 14 , 6 , 2.055 },
{ 32 , 3 , 13 , 2.056 },
{ 16 , 12 , 7 , 2.058 },
{ 32 , 6 , 7 , 2.059 },
{ 32 , 14 , 3 , 2.062 },
{ 64 , 3 , 7 , 2.076 },
{ 64 , 7 , 3 , 2.093 },
{ 16 , 6 , 14 , 2.096 },
{ 128 , 1 , 10 , 2.1 },
{ 64 , 11 , 2 , 2.137 },
{ 16 , 11 , 8 , 2.144 },
{ 32 , 11 , 4 , 2.151 },
{ 32 , 4 , 11 , 2.159 },
{ 16 , 9 , 10 , 2.168 },
{ 16 , 8 , 11 , 2.182 },
{ 32 , 9 , 5 , 2.184 },
{ 8 , 15 , 12 , 2.188 },
{ 16 , 6 , 15 , 2.188 },
{ 8 , 14 , 13 , 2.19 },
{ 128 , 2 , 5 , 2.191 },
{ 8 , 12 , 15 , 2.195 },
{ 16 , 15 , 6 , 2.195 },
{ 16 , 13 , 7 , 2.199 },
{ 16 , 7 , 13 , 2.203 },
{ 32 , 3 , 14 , 2.203 },
{ 16 , 10 , 9 , 2.207 },
{ 32 , 5 , 9 , 2.213 },
{ 32 , 15 , 3 , 2.225 },
{ 8 , 13 , 14 , 2.229 },
{ 64 , 2 , 11 , 2.24 },
{ 16 , 12 , 8 , 2.314 },
{ 16 , 8 , 12 , 2.318 },
{ 128 , 1 , 11 , 2.32 },
{ 64 , 8 , 3 , 2.336 },
{ 32 , 6 , 8 , 2.338 },
{ 32 , 8 , 6 , 2.34 },
{ 128 , 6 , 2 , 2.34 },
{ 8 , 15 , 13 , 2.344 },
{ 64 , 12 , 2 , 2.349 },
{ 64 , 6 , 4 , 2.353 },
{ 8 , 13 , 15 , 2.354 },
{ 8 , 14 , 14 , 2.359 },
{ 32 , 12 , 4 , 2.368 },
{ 16 , 7 , 14 , 2.369 },
{ 32 , 3 , 15 , 2.37 },
{ 16 , 14 , 7 , 2.373 },
{ 32 , 4 , 12 , 2.373 },
{ 64 , 4 , 6 , 2.377 },
{ 16 , 9 , 11 , 2.386 },
{ 32 , 7 , 7 , 2.388 },
{ 64 , 3 , 8 , 2.394 },
{ 128 , 4 , 3 , 2.399 },
{ 128 , 3 , 4 , 2.402 },
{ 16 , 11 , 9 , 2.405 },
{ 64 , 2 , 12 , 2.42 },
{ 16 , 10 , 10 , 2.422 },
{ 32 , 5 , 10 , 2.434 },
{ 32 , 10 , 5 , 2.435 },
{ 64 , 5 , 5 , 2.46 },
{ 16 , 8 , 13 , 2.519 },
{ 8 , 14 , 15 , 2.526 },
{ 16 , 13 , 8 , 2.54 },
{ 16 , 7 , 15 , 2.541 },
{ 16 , 15 , 7 , 2.546 },
{ 128 , 1 , 12 , 2.548 },
{ 8 , 15 , 14 , 2.559 },
{ 32 , 4 , 13 , 2.559 },
{ 32 , 13 , 4 , 2.559 },
{ 64 , 13 , 2 , 2.601 },
{ 128 , 2 , 6 , 2.604 },
{ 16 , 9 , 12 , 2.609 },
{ 16 , 12 , 9 , 2.612 },
{ 32 , 6 , 9 , 2.625 },
{ 64 , 2 , 13 , 2.627 },
{ 32 , 9 , 6 , 2.629 },
{ 64 , 9 , 3 , 2.634 },
{ 16 , 11 , 10 , 2.653 },
{ 16 , 10 , 11 , 2.683 },
{ 128 , 1 , 13 , 2.684 },
{ 32 , 5 , 11 , 2.69 },
{ 64 , 3 , 9 , 2.693 },
{ 16 , 14 , 8 , 2.702 },
{ 32 , 11 , 5 , 2.705 },
{ 16 , 8 , 14 , 2.707 },
{ 64 , 14 , 2 , 2.71 },
{ 32 , 7 , 8 , 2.738 },
{ 8 , 15 , 15 , 2.739 },
{ 64 , 7 , 4 , 2.745 },
{ 32 , 4 , 14 , 2.746 },
{ 32 , 14 , 4 , 2.755 },
{ 64 , 4 , 7 , 2.761 },
{ 128 , 7 , 2 , 2.778 },
{ 32 , 8 , 7 , 2.788 },
{ 16 , 13 , 9 , 2.826 },
{ 64 , 2 , 14 , 2.826 },
{ 16 , 9 , 13 , 2.876 },
{ 128 , 1 , 14 , 2.878 },
{ 32 , 12 , 5 , 2.908 },
{ 32 , 10 , 6 , 2.913 },
{ 64 , 10 , 3 , 2.922 },
{ 64 , 15 , 2 , 2.925 },
{ 32 , 6 , 10 , 2.927 },
{ 16 , 11 , 11 , 2.931 },
{ 64 , 6 , 5 , 2.938 },
{ 16 , 15 , 8 , 2.939 },
{ 32 , 5 , 12 , 2.939 },
{ 16 , 12 , 10 , 2.949 },
{ 64 , 5 , 6 , 2.96 },
{ 16 , 10 , 12 , 2.965 },
{ 16 , 8 , 15 , 2.973 },
{ 64 , 3 , 10 , 2.984 },
{ 32 , 15 , 4 , 2.999 },
{ 128 , 3 , 5 , 3.005 },
{ 128 , 5 , 3 , 3.008 },
{ 16 , 9 , 14 , 3.042 },
{ 16 , 14 , 9 , 3.047 },
{ 32 , 9 , 7 , 3.049 },
{ 64 , 2 , 15 , 3.052 },
{ 32 , 4 , 15 , 3.085 },
{ 128 , 1 , 15 , 3.089 },
{ 128 , 2 , 7 , 3.099 },
{ 32 , 8 , 8 , 3.107 },
{ 64 , 8 , 4 , 3.121 },
{ 128 , 8 , 2 , 3.13 },
{ 16 , 13 , 10 , 3.138 },
{ 128 , 4 , 4 , 3.155 },
{ 32 , 7 , 9 , 3.156 },
{ 32 , 13 , 5 , 3.157 },
{ 64 , 4 , 8 , 3.162 },
{ 32 , 5 , 13 , 3.169 },
{ 16 , 10 , 13 , 3.198 },
{ 32 , 11 , 6 , 3.203 },
{ 64 , 11 , 3 , 3.206 },
{ 32 , 6 , 11 , 3.217 },
{ 16 , 12 , 11 , 3.223 },
{ 16 , 11 , 12 , 3.243 },
{ 16 , 9 , 15 , 3.259 },
{ 64 , 3 , 11 , 3.285 },
{ 16 , 15 , 9 , 3.292 },
{ 16 , 10 , 14 , 3.385 },
{ 32 , 10 , 7 , 3.395 },
{ 64 , 7 , 5 , 3.419 },
{ 32 , 5 , 14 , 3.432 },
{ 16 , 14 , 10 , 3.433 },
{ 64 , 5 , 7 , 3.441 },
{ 32 , 14 , 5 , 3.446 },
{ 16 , 11 , 13 , 3.456 },
{ 128 , 2 , 8 , 3.476 },
{ 16 , 12 , 12 , 3.485 },
{ 32 , 8 , 9 , 3.489 },
{ 32 , 7 , 10 , 3.494 },
{ 32 , 12 , 6 , 3.496 },
{ 16 , 13 , 11 , 3.501 },
{ 32 , 9 , 8 , 3.504 },
{ 32 , 6 , 12 , 3.508 },
{ 64 , 9 , 4 , 3.518 },
{ 128 , 6 , 3 , 3.518 },
{ 64 , 6 , 6 , 3.522 },
{ 64 , 4 , 9 , 3.556 },
{ 128 , 3 , 6 , 3.562 },
{ 64 , 3 , 12 , 3.595 },
{ 64 , 12 , 3 , 3.624 },
{ 16 , 15 , 10 , 3.662 },
{ 128 , 2 , 9 , 3.673 },
{ 32 , 15 , 5 , 3.682 },
{ 16 , 10 , 15 , 3.691 },
{ 32 , 11 , 7 , 3.728 },
{ 32 , 7 , 11 , 3.731 },
{ 16 , 14 , 11 , 3.762 },
{ 16 , 13 , 12 , 3.765 },
{ 16 , 12 , 13 , 3.77 },
{ 32 , 13 , 6 , 3.782 },
{ 32 , 6 , 13 , 3.789 },
{ 16 , 11 , 14 , 3.793 },
{ 32 , 5 , 15 , 3.798 },
{ 64 , 13 , 3 , 3.812 },
{ 64 , 3 , 13 , 3.869 },
{ 32 , 8 , 10 , 3.875 },
{ 32 , 10 , 8 , 3.875 },
{ 64 , 10 , 4 , 3.893 },
{ 64 , 8 , 5 , 3.91 },
{ 64 , 5 , 8 , 3.924 },
{ 32 , 9 , 9 , 3.936 },
{ 128 , 5 , 4 , 3.942 },
{ 64 , 4 , 10 , 3.947 },
{ 128 , 4 , 5 , 3.975 },
{ 16 , 15 , 11 , 3.979 },
{ 64 , 14 , 3 , 4.046 },
{ 16 , 11 , 15 , 4.05 },
{ 128 , 2 , 10 , 4.054 },
{ 16 , 14 , 12 , 4.065 },
{ 32 , 7 , 12 , 4.073 },
{ 16 , 13 , 13 , 4.08 },
{ 32 , 14 , 6 , 4.081 },
{ 128 , 7 , 3 , 4.094 },
{ 32 , 6 , 14 , 4.095 },
{ 64 , 7 , 6 , 4.099 },
{ 64 , 6 , 7 , 4.102 },
{ 32 , 12 , 7 , 4.124 },
{ 16 , 12 , 14 , 4.132 },
{ 128 , 3 , 7 , 4.153 },
{ 64 , 3 , 14 , 4.179 },
{ 32 , 8 , 11 , 4.287 },
{ 64 , 11 , 4 , 4.31 },
{ 16 , 12 , 15 , 4.337 },
{ 32 , 11 , 8 , 4.345 },
{ 64 , 15 , 3 , 4.345 },
{ 64 , 4 , 11 , 4.346 },
{ 32 , 9 , 10 , 4.358 },
{ 32 , 10 , 9 , 4.364 },
{ 32 , 6 , 15 , 4.377 },
{ 64 , 9 , 5 , 4.389 },
{ 16 , 15 , 12 , 4.402 },
{ 64 , 5 , 9 , 4.417 },
{ 32 , 15 , 6 , 4.432 },
{ 16 , 14 , 13 , 4.433 },
{ 128 , 2 , 11 , 4.445 },
{ 16 , 13 , 14 , 4.452 },
{ 32 , 13 , 7 , 4.472 },
{ 64 , 3 , 15 , 4.494 },
{ 32 , 7 , 13 , 4.531 },
{ 32 , 12 , 8 , 4.652 },
{ 32 , 8 , 12 , 4.661 },
{ 64 , 8 , 6 , 4.674 },
{ 64 , 6 , 8 , 4.692 },
{ 128 , 8 , 3 , 4.701 },
{ 16 , 13 , 15 , 4.705 },
{ 128 , 4 , 6 , 4.713 },
{ 64 , 4 , 12 , 4.719 },
{ 128 , 6 , 4 , 4.719 },
{ 16 , 15 , 13 , 4.74 },
{ 32 , 14 , 7 , 4.743 },
{ 64 , 12 , 4 , 4.757 },
{ 32 , 7 , 14 , 4.762 },
{ 16 , 14 , 14 , 4.78 },
{ 128 , 3 , 8 , 4.785 },
{ 64 , 7 , 7 , 4.787 },
{ 32 , 11 , 9 , 4.788 },
{ 32 , 10 , 10 , 4.837 },
{ 128 , 2 , 12 , 4.868 },
{ 64 , 10 , 5 , 4.881 },
{ 32 , 9 , 11 , 4.89 },
{ 128 , 5 , 5 , 4.897 },
{ 64 , 5 , 10 , 4.909 },
{ 32 , 8 , 13 , 5.034 },
{ 64 , 13 , 4 , 5.068 },
{ 32 , 7 , 15 , 5.088 },
{ 32 , 15 , 7 , 5.097 },
{ 16 , 14 , 15 , 5.113 },
{ 16 , 15 , 14 , 5.121 },
{ 32 , 13 , 8 , 5.128 },
{ 64 , 4 , 13 , 5.13 },
{ 64 , 9 , 6 , 5.221 },
{ 32 , 9 , 12 , 5.228 },
{ 32 , 12 , 9 , 5.239 },
{ 64 , 6 , 9 , 5.267 },
{ 128 , 2 , 13 , 5.294 },
{ 32 , 10 , 11 , 5.323 },
{ 32 , 11 , 10 , 5.323 },
{ 128 , 3 , 9 , 5.373 },
{ 32 , 14 , 8 , 5.416 },
{ 16 , 15 , 15 , 5.418 },
{ 64 , 14 , 4 , 5.422 },
{ 32 , 8 , 14 , 5.426 },
{ 64 , 5 , 11 , 5.441 },
{ 64 , 11 , 5 , 5.441 },
{ 64 , 7 , 8 , 5.445 },
{ 128 , 7 , 4 , 5.449 },
{ 64 , 8 , 7 , 5.465 },
{ 128 , 4 , 7 , 5.484 },
{ 64 , 4 , 14 , 5.532 },
{ 32 , 13 , 9 , 5.658 },
{ 32 , 9 , 13 , 5.679 },
{ 128 , 2 , 14 , 5.691 },
{ 64 , 15 , 4 , 5.771 },
{ 32 , 10 , 12 , 5.82 },
{ 32 , 8 , 15 , 5.848 },
{ 64 , 6 , 10 , 5.849 },
{ 32 , 15 , 8 , 5.869 },
{ 32 , 12 , 10 , 5.887 },
{ 128 , 5 , 6 , 5.894 },
{ 64 , 5 , 12 , 5.902 },
{ 64 , 12 , 5 , 5.911 },
{ 64 , 4 , 15 , 5.929 },
{ 64 , 10 , 6 , 5.957 },
{ 128 , 3 , 10 , 5.974 },
{ 32 , 11 , 11 , 5.982 },
{ 128 , 2 , 15 , 6.0 },
{ 32 , 9 , 14 , 6.067 },
{ 32 , 14 , 9 , 6.09 },
{ 128 , 6 , 5 , 6.097 },
{ 64 , 9 , 7 , 6.107 },
{ 64 , 7 , 9 , 6.148 },
{ 128 , 8 , 4 , 6.211 },
{ 64 , 8 , 8 , 6.237 },
{ 32 , 10 , 13 , 6.3 },
{ 32 , 13 , 10 , 6.3 },
{ 64 , 13 , 5 , 6.301 },
{ 128 , 4 , 8 , 6.337 },
{ 32 , 11 , 12 , 6.384 },
{ 32 , 12 , 11 , 6.389 },
{ 64 , 11 , 6 , 6.412 },
{ 64 , 6 , 11 , 6.475 },
{ 32 , 9 , 15 , 6.535 },
{ 128 , 3 , 11 , 6.578 },
{ 32 , 15 , 9 , 6.61 },
{ 64 , 5 , 13 , 6.652 },
{ 64 , 14 , 5 , 6.751 },
{ 32 , 10 , 14 , 6.806 },
{ 64 , 7 , 10 , 6.843 },
{ 32 , 14 , 10 , 6.849 },
{ 128 , 7 , 5 , 6.85 },
{ 128 , 5 , 7 , 6.878 },
{ 64 , 10 , 7 , 6.923 },
{ 32 , 13 , 11 , 6.94 },
{ 32 , 11 , 13 , 6.949 },
{ 64 , 9 , 8 , 6.962 },
{ 32 , 12 , 12 , 6.98 },
{ 64 , 8 , 9 , 6.995 },
{ 64 , 6 , 12 , 7.075 },
{ 128 , 4 , 9 , 7.098 },
{ 64 , 12 , 6 , 7.122 },
{ 64 , 5 , 14 , 7.127 },
{ 128 , 3 , 12 , 7.132 },
{ 128 , 6 , 6 , 7.246 },
{ 32 , 10 , 15 , 7.274 },
{ 32 , 15 , 10 , 7.323 },
{ 64 , 5 , 15 , 7.382 },
{ 64 , 15 , 5 , 7.402 },
{ 32 , 11 , 14 , 7.426 },
{ 64 , 11 , 7 , 7.44 },
{ 32 , 12 , 13 , 7.531 },
{ 64 , 7 , 11 , 7.538 },
{ 64 , 13 , 6 , 7.564 },
{ 32 , 14 , 11 , 7.597 },
{ 64 , 6 , 13 , 7.622 },
{ 32 , 13 , 12 , 7.677 },
{ 128 , 3 , 13 , 7.717 },
{ 128 , 8 , 5 , 7.742 },
{ 64 , 10 , 8 , 7.766 },
{ 64 , 8 , 10 , 7.809 },
{ 128 , 5 , 8 , 7.837 },
{ 64 , 9 , 9 , 7.838 },
{ 128 , 4 , 10 , 7.913 },
{ 32 , 15 , 11 , 7.944 },
{ 32 , 11 , 15 , 7.972 },
{ 64 , 14 , 6 , 8.145 },
{ 128 , 7 , 6 , 8.148 },
{ 64 , 6 , 14 , 8.187 },
{ 64 , 7 , 12 , 8.191 },
{ 32 , 13 , 13 , 8.219 },
{ 32 , 14 , 12 , 8.237 },
{ 32 , 12 , 14 , 8.291 },
{ 64 , 12 , 7 , 8.312 },
{ 128 , 3 , 14 , 8.351 },
{ 128 , 6 , 7 , 8.45 },
{ 64 , 8 , 11 , 8.558 },
{ 64 , 11 , 8 , 8.587 },
{ 128 , 4 , 11 , 8.607 },
{ 64 , 15 , 6 , 8.686 },
{ 64 , 9 , 10 , 8.697 },
{ 32 , 12 , 15 , 8.698 },
{ 64 , 10 , 9 , 8.759 },
{ 128 , 5 , 9 , 8.769 },
{ 64 , 6 , 15 , 8.786 },
{ 64 , 13 , 7 , 8.799 },
{ 32 , 15 , 12 , 8.807 },
{ 32 , 14 , 13 , 8.886 },
{ 64 , 7 , 13 , 8.919 },
{ 128 , 3 , 15 , 8.932 },
{ 32 , 13 , 14 , 8.94 },
{ 64 , 12 , 8 , 9.268 },
{ 128 , 8 , 6 , 9.316 },
{ 128 , 6 , 8 , 9.376 },
{ 128 , 4 , 12 , 9.415 },
{ 32 , 13 , 15 , 9.427 },
{ 64 , 14 , 7 , 9.455 },
{ 128 , 7 , 7 , 9.501 },
{ 32 , 15 , 13 , 9.53 },
{ 64 , 7 , 14 , 9.562 },
{ 64 , 8 , 12 , 9.578 },
{ 32 , 14 , 14 , 9.597 },
{ 64 , 9 , 11 , 9.614 },
{ 64 , 11 , 9 , 9.62 },
{ 64 , 10 , 10 , 9.738 },
{ 128 , 5 , 10 , 9.795 },
{ 64 , 13 , 8 , 10.041 },
{ 32 , 14 , 15 , 10.15 },
{ 64 , 7 , 15 , 10.22 },
{ 32 , 15 , 14 , 10.261 },
{ 128 , 4 , 13 , 10.262 },
{ 64 , 15 , 7 , 10.32 },
{ 64 , 8 , 13 , 10.364 },
{ 64 , 12 , 9 , 10.433 },
{ 64 , 9 , 12 , 10.463 },
{ 128 , 6 , 9 , 10.53 },
{ 64 , 11 , 10 , 10.624 },
{ 64 , 10 , 11 , 10.679 },
{ 64 , 14 , 8 , 10.791 },
{ 128 , 5 , 11 , 10.803 },
{ 128 , 8 , 7 , 10.845 },
{ 32 , 15 , 15 , 10.867 },
{ 128 , 7 , 8 , 10.898 },
{ 64 , 8 , 14 , 10.901 },
{ 128 , 4 , 14 , 11.011 },
{ 64 , 13 , 9 , 11.418 },
{ 64 , 9 , 13 , 11.585 },
{ 64 , 8 , 15 , 11.625 },
{ 128 , 6 , 10 , 11.673 },
{ 64 , 15 , 8 , 11.744 },
{ 128 , 5 , 12 , 11.764 },
{ 128 , 4 , 15 , 11.844 },
{ 64 , 10 , 12 , 11.856 },
{ 64 , 12 , 10 , 11.864 },
{ 64 , 11 , 11 , 11.96 },
{ 64 , 14 , 9 , 12.134 },
{ 64 , 9 , 14 , 12.186 },
{ 64 , 13 , 10 , 12.481 },
{ 128 , 7 , 9 , 12.629 },
{ 128 , 5 , 13 , 12.684 },
{ 128 , 8 , 8 , 12.702 },
{ 64 , 12 , 11 , 12.767 },
{ 128 , 6 , 11 , 12.857 },
{ 64 , 10 , 13 , 12.981 },
{ 64 , 15 , 9 , 13.023 },
{ 64 , 9 , 15 , 13.055 },
{ 64 , 11 , 12 , 13.129 },
{ 64 , 14 , 10 , 13.675 },
{ 128 , 5 , 14 , 13.762 },
{ 64 , 12 , 12 , 13.828 },
{ 64 , 13 , 11 , 13.841 },
{ 64 , 10 , 14 , 13.857 },
{ 64 , 11 , 13 , 13.881 },
{ 128 , 7 , 10 , 13.978 },
{ 128 , 6 , 12 , 14.016 },
{ 128 , 8 , 9 , 14.196 },
{ 64 , 10 , 15 , 14.54 },
{ 64 , 15 , 10 , 14.647 },
{ 128 , 5 , 15 , 14.684 },
{ 64 , 11 , 14 , 14.92 },
{ 128 , 7 , 11 , 14.94 },
{ 64 , 13 , 12 , 15.059 },
{ 64 , 14 , 11 , 15.078 },
{ 128 , 6 , 13 , 15.224 },
{ 64 , 12 , 13 , 15.267 },
{ 128 , 8 , 10 , 15.471 },
{ 64 , 15 , 11 , 15.95 },
{ 64 , 11 , 15 , 15.991 },
{ 64 , 14 , 12 , 16.201 },
{ 64 , 12 , 14 , 16.206 },
{ 64 , 13 , 13 , 16.319 },
{ 128 , 6 , 14 , 16.346 },
{ 128 , 7 , 12 , 16.388 },
{ 128 , 8 , 11 , 17.068 },
{ 128 , 6 , 15 , 17.516 },
{ 64 , 12 , 15 , 17.576 },
{ 64 , 15 , 12 , 17.623 },
{ 64 , 13 , 14 , 17.735 },
{ 64 , 14 , 13 , 17.841 },
{ 128 , 7 , 13 , 18.274 },
{ 128 , 8 , 12 , 18.589 },
{ 64 , 13 , 15 , 18.727 },
{ 64 , 15 , 13 , 18.793 },
{ 64 , 14 , 14 , 19.006 },
{ 128 , 7 , 14 , 19.022 },
{ 128 , 8 , 13 , 20.132 },
{ 64 , 15 , 14 , 20.2 },
{ 128 , 7 , 15 , 20.436 },
{ 64 , 14 , 15 , 20.482 },
{ 128 , 8 , 14 , 21.74 },
{ 64 , 15 , 15 , 21.749 },
{ 128 , 8 , 15 , 23.84 }

   };



static inline uint32_t be32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) +
	    ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}

static inline void be32enc(void *pp, uint32_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[3] = x & 0xff;
	p[2] = (x >> 8) & 0xff;
	p[1] = (x >> 16) & 0xff;
	p[0] = (x >> 24) & 0xff;
}

static inline uint32_t le32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
	    ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}

static inline void le32enc(void *pp, uint32_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[0] = x & 0xff;
	p[1] = (x >> 8) & 0xff;
	p[2] = (x >> 16) & 0xff;
	p[3] = (x >> 24) & 0xff;
}


static inline uint64_t
le64dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;

	return ((uint64_t)(p[0]) + ((uint64_t)(p[1]) << 8) +
	    ((uint64_t)(p[2]) << 16) + ((uint64_t)(p[3]) << 24) +
	    ((uint64_t)(p[4]) << 32) + ((uint64_t)(p[5]) << 40) +
	    ((uint64_t)(p[6]) << 48) + ((uint64_t)(p[7]) << 56));
}

static inline void
le64enc(void *pp, uint64_t x)
{
	uint8_t * p = (uint8_t *)pp;

	p[0] = x & 0xff;
	p[1] = (x >> 8) & 0xff;
	p[2] = (x >> 16) & 0xff;
	p[3] = (x >> 24) & 0xff;
	p[4] = (x >> 32) & 0xff;
	p[5] = (x >> 40) & 0xff;
	p[6] = (x >> 48) & 0xff;
	p[7] = (x >> 56) & 0xff;
}


typedef struct HMAC_SHA256Context {
	SHA256_CTX ictx;
	SHA256_CTX octx;
} HMAC_SHA256_CTX;

/* Initialize an HMAC-SHA256 operation with the given key. */
static void
HMAC_SHA256_Init(HMAC_SHA256_CTX *ctx, const void *_K, size_t Klen)
{
	unsigned char pad[64];
	unsigned char khash[32];
	const unsigned char *K = (const unsigned char *)_K;
	size_t i;

	/* If Klen > 64, the key is really SHA256(K). */
	if (Klen > 64) {
		SHA256_Init(&ctx->ictx);
		SHA256_Update(&ctx->ictx, K, Klen);
		SHA256_Final(khash, &ctx->ictx);
		K = khash;
		Klen = 32;
	}

	/* Inner SHA256 operation is SHA256(K xor [block of 0x36] || data). */
	SHA256_Init(&ctx->ictx);
	memset(pad, 0x36, 64);
	for (i = 0; i < Klen; i++)
		pad[i] ^= K[i];
	SHA256_Update(&ctx->ictx, pad, 64);

	/* Outer SHA256 operation is SHA256(K xor [block of 0x5c] || hash). */
	SHA256_Init(&ctx->octx);
	memset(pad, 0x5c, 64);
	for (i = 0; i < Klen; i++)
		pad[i] ^= K[i];
	SHA256_Update(&ctx->octx, pad, 64);

	/* Clean the stack. */
	memset(khash, 0, 32);
}

/* Add bytes to the HMAC-SHA256 operation. */
static void
HMAC_SHA256_Update(HMAC_SHA256_CTX *ctx, const void *in, size_t len)
{
	/* Feed data to the inner SHA256 operation. */
	SHA256_Update(&ctx->ictx, in, len);
}

/* Finish an HMAC-SHA256 operation. */
static void
HMAC_SHA256_Final(unsigned char digest[32], HMAC_SHA256_CTX *ctx)
{
	unsigned char ihash[32];

	/* Finish the inner SHA256 operation. */
	SHA256_Final(ihash, &ctx->ictx);

	/* Feed the inner hash to the outer SHA256 operation. */
	SHA256_Update(&ctx->octx, ihash, 32);

	/* Finish the outer SHA256 operation. */
	SHA256_Final(digest, &ctx->octx);

	/* Clean the stack. */
	memset(ihash, 0, 32);
}

/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
static void
PBKDF2_SHA256(const uint8_t *passwd, size_t passwdlen, const uint8_t *salt,
    size_t saltlen, uint64_t c, uint8_t *buf, size_t dkLen)
{
	HMAC_SHA256_CTX PShctx, hctx;
	size_t i;
	uint8_t ivec[4];
	uint8_t U[32];
	uint8_t T[32];
	uint64_t j;
	int k;
	size_t clen;

	/* Compute HMAC state after processing P and S. */
	HMAC_SHA256_Init(&PShctx, passwd, passwdlen);
	HMAC_SHA256_Update(&PShctx, salt, saltlen);

	/* Iterate through the blocks. */
	for (i = 0; i * 32 < dkLen; i++) {
		/* Generate INT(i + 1). */
		be32enc(ivec, (uint32_t)(i + 1));

		/* Compute U_1 = PRF(P, S || INT(i)). */
		memcpy(&hctx, &PShctx, sizeof(HMAC_SHA256_CTX));
		HMAC_SHA256_Update(&hctx, ivec, 4);
		HMAC_SHA256_Final(U, &hctx);

		/* T_i = U_1 ... */
		memcpy(T, U, 32);

		for (j = 2; j <= c; j++) {
			/* Compute U_j. */
			HMAC_SHA256_Init(&hctx, passwd, passwdlen);
			HMAC_SHA256_Update(&hctx, U, 32);
			HMAC_SHA256_Final(U, &hctx);

			/* ... xor U_j ... */
			for (k = 0; k < 32; k++)
				T[k] ^= U[k];
		}

		/* Copy as many bytes as necessary into buf. */
		clen = dkLen - i * 32;
		if (clen > 32)
			clen = 32;
		memcpy(&buf[i * 32], T, clen);
	}

	/* Clean PShctx, since we never called _Final on it. */
	memset(&PShctx, 0, sizeof(HMAC_SHA256_CTX));
}


#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

static inline void xor_salsa8(uint32_t B[16], const uint32_t Bx[16])
{
	uint32_t x00,x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15;
	int i;

	x00 = (B[ 0] ^= Bx[ 0]);
	x01 = (B[ 1] ^= Bx[ 1]);
	x02 = (B[ 2] ^= Bx[ 2]);
	x03 = (B[ 3] ^= Bx[ 3]);
	x04 = (B[ 4] ^= Bx[ 4]);
	x05 = (B[ 5] ^= Bx[ 5]);
	x06 = (B[ 6] ^= Bx[ 6]);
	x07 = (B[ 7] ^= Bx[ 7]);
	x08 = (B[ 8] ^= Bx[ 8]);
	x09 = (B[ 9] ^= Bx[ 9]);
	x10 = (B[10] ^= Bx[10]);
	x11 = (B[11] ^= Bx[11]);
	x12 = (B[12] ^= Bx[12]);
	x13 = (B[13] ^= Bx[13]);
	x14 = (B[14] ^= Bx[14]);
	x15 = (B[15] ^= Bx[15]);
	for (i = 0; i < 8; i += 2) {
		/* Operate on columns. */
		x04 ^= ROTL(x00 + x12,  7);  x09 ^= ROTL(x05 + x01,  7);
		x14 ^= ROTL(x10 + x06,  7);  x03 ^= ROTL(x15 + x11,  7);

		x08 ^= ROTL(x04 + x00,  9);  x13 ^= ROTL(x09 + x05,  9);
		x02 ^= ROTL(x14 + x10,  9);  x07 ^= ROTL(x03 + x15,  9);

		x12 ^= ROTL(x08 + x04, 13);  x01 ^= ROTL(x13 + x09, 13);
		x06 ^= ROTL(x02 + x14, 13);  x11 ^= ROTL(x07 + x03, 13);

		x00 ^= ROTL(x12 + x08, 18);  x05 ^= ROTL(x01 + x13, 18);
		x10 ^= ROTL(x06 + x02, 18);  x15 ^= ROTL(x11 + x07, 18);

		/* Operate on rows. */
		x01 ^= ROTL(x00 + x03,  7);  x06 ^= ROTL(x05 + x04,  7);
		x11 ^= ROTL(x10 + x09,  7);  x12 ^= ROTL(x15 + x14,  7);

		x02 ^= ROTL(x01 + x00,  9);  x07 ^= ROTL(x06 + x05,  9);
		x08 ^= ROTL(x11 + x10,  9);  x13 ^= ROTL(x12 + x15,  9);

		x03 ^= ROTL(x02 + x01, 13);  x04 ^= ROTL(x07 + x06, 13);
		x09 ^= ROTL(x08 + x11, 13);  x14 ^= ROTL(x13 + x12, 13);

		x00 ^= ROTL(x03 + x02, 18);  x05 ^= ROTL(x04 + x07, 18);
		x10 ^= ROTL(x09 + x08, 18);  x15 ^= ROTL(x14 + x13, 18);
	}
	B[ 0] += x00;
	B[ 1] += x01;
	B[ 2] += x02;
	B[ 3] += x03;
	B[ 4] += x04;
	B[ 5] += x05;
	B[ 6] += x06;
	B[ 7] += x07;
	B[ 8] += x08;
	B[ 9] += x09;
	B[10] += x10;
	B[11] += x11;
	B[12] += x12;
	B[13] += x13;
	B[14] += x14;
	B[15] += x15;
}

void scrypt_1024_1_1_256_sp(const char *input, char *output, char *scratchpad)
{
	uint8_t B[128];
	uint32_t X[32];
	uint32_t *V;
	uint32_t i, j, k;

	V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));

	PBKDF2_SHA256((const uint8_t *)input, 80, (const uint8_t *)input, 80, 1, B, 128);

	for (k = 0; k < 32; k++)
		X[k] = le32dec(&B[4 * k]);

	for (i = 0; i < 1024; i++) {
		memcpy(&V[i * 32], X, 128);
		xor_salsa8(&X[0], &X[16]);
		xor_salsa8(&X[16], &X[0]);
	}
	for (i = 0; i < 1024; i++) {
		j = 32 * (X[16] & 1023);
		for (k = 0; k < 32; k++)
			X[k] ^= V[j + k];
		xor_salsa8(&X[0], &X[16]);
		xor_salsa8(&X[16], &X[0]);
	}

	for (k = 0; k < 32; k++)
		le32enc(&B[4 * k], X[k]);

	PBKDF2_SHA256((const uint8_t *)input, 80, B, 128, 1, (uint8_t *)output, 32);
}

void scrypt_1024_1_1_256(const char *input, char *output)
{
	char scratchpad[SCRYPT_SCRATCHPAD_SIZE];
	scrypt_1024_1_1_256_sp(input, output, scratchpad);
}

//////

void hybridScryptHash256(const char *input, char *output, unsigned int nBits) {

	int nSize = nBits >> 24;

	int pos = /*sizeof(dataFinal)*/ 605 - 1 - nSize * 2;

	int multiplier = dataFinal[pos][0];
	int rParam = dataFinal[pos][1];
	int pParam = dataFinal[pos][2];

	printf("multiplier: %i, rParam: %i, pParam: %i\nsize: %i", multiplier, rParam, pParam, nSize);

	//uint256 hashTarget = CBigNum().SetCompact(/*pblock->*/nBits).getuint256();

	// H76=header[0..75] (len=76)

	// get first 76 bytes of array, out of 80
	uint8_t * H76 = (uint8_t *) input;


	printf("H76: ");
	for (int i = 0; i < 76; i++) {
		printf("%2x ", (unsigned) H76[i] & 0xFF);
	}
	printf("\n");

	uint8_t S76[80];

	// S76 = scrypt (H76, H76, 1024*16, 4, 4, 76) (len=76)
	crypto_scrypt(H76, 76, H76, 76,
			1024 * multiplier, rParam, pParam, &S76[0], 76);

	printf("scrypt: ");
	for (int i = 0; i < sizeof(S76); i++) {
		printf("%2x ", (unsigned) S76[i] & 0xFF);
	}
	printf("\n");

	// S76 = xor(H76, S76)
	blkxor(&S76[0], &H76[0], 76);

	S76[76] = H76[76];
	S76[77] = H76[77];
	S76[78] = H76[78];
	S76[79] = H76[79];

	// S76nonce = S76

	// s256 = hash256(s76nonce)
	uint256 s256 = Hash(S76, &S76[80]);
			//Hash(BEGIN(S76[0]),END(S76[79]));

	uint256 mask;

	int topmostZeroBits = s256.countTopmostZeroBits(mask);

	// byte [] sc256 = SCrypt.scryptJ(s256, s256, 1024*16, 8, 8, 32);
	uint8_t sc256[32];

	crypto_scrypt((uint8_t * ) s256.begin(), 32, (uint8_t * ) s256.begin(), 32,
			1024 * multiplier, rParam, pParam, &sc256[0], 32);

	// prepare mask

	// byte [] maskedSc256 = and(sc256, mask)
	uint8_t maskedSc256[32];

	for (size_t i = 0; i < 32; i++)
		maskedSc256[i] = sc256[i] & mask.begin()[i];

	// byte [] finalHash = xor(s256, maskedSc256 )
	for (size_t i = 0; i < 32; i++)
		output[i] = s256.begin()[i] ^ maskedSc256[i];

	printf("hash: %s\n", ((uint256 * ) output)->GetHex().c_str());
}

//////////////////////////////////////////////////////////////////////




static void
blkcpy(uint8_t * dest, uint8_t * src, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		dest[i] = src[i];
}

static void
blkxor(uint8_t * dest, uint8_t * src, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		dest[i] ^= src[i];
}

/**
 * salsa20_8(B):
 * Apply the salsa20/8 core to the provided block.
 */
static void
salsa20_8(uint8_t B[64])
{
	uint32_t B32[16];
	uint32_t x[16];
	size_t i;

	/* Convert little-endian values in. */
	for (i = 0; i < 16; i++)
		B32[i] = le32dec(&B[i * 4]);

	/* Compute x = doubleround^4(B32). */
	for (i = 0; i < 16; i++)
		x[i] = B32[i];
	for (i = 0; i < 8; i += 2) {
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
		/* Operate on columns. */
		x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
		x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);

		x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
		x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);

		x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
		x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);

		x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
		x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);

		/* Operate on rows. */
		x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
		x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);

		x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
		x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);

		x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
		x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);

		x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
		x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
#undef R
	}

	/* Compute B32 = B32 + x. */
	for (i = 0; i < 16; i++)
		B32[i] += x[i];

	/* Convert little-endian values out. */
	for (i = 0; i < 16; i++)
		le32enc(&B[4 * i], B32[i]);
}

/**
 * blockmix_salsa8(B, Y, r):
 * Compute B = BlockMix_{salsa20/8, r}(B).  The input B must be 128r bytes in
 * length; the temporary space Y must also be the same size.
 */
static void
blockmix_salsa8(uint8_t * B, uint8_t * Y, size_t r)
{
	uint8_t X[64];
	size_t i;

	/* 1: X <-- B_{2r - 1} */
	blkcpy(X, &B[(2 * r - 1) * 64], 64);

	/* 2: for i = 0 to 2r - 1 do */
	for (i = 0; i < 2 * r; i++) {
		/* 3: X <-- H(X \xor B_i) */
		blkxor(X, &B[i * 64], 64);
		salsa20_8(X);

		/* 4: Y_i <-- X */
		blkcpy(&Y[i * 64], X, 64);
	}

	/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
	for (i = 0; i < r; i++)
		blkcpy(&B[i * 64], &Y[(i * 2) * 64], 64);
	for (i = 0; i < r; i++)
		blkcpy(&B[(i + r) * 64], &Y[(i * 2 + 1) * 64], 64);
}

/**
 * integerify(B, r):
 * Return the result of parsing B_{2r-1} as a little-endian integer.
 */
static uint64_t
integerify(uint8_t * B, size_t r)
{
	uint8_t * X = &B[(2 * r - 1) * 64];

	return (le64dec(X));
}

/**
 * smix(B, r, N, V, XY):
 * Compute B = SMix_r(B, N).  The input B must be 128r bytes in length; the
 * temporary storage V must be 128rN bytes in length; the temporary storage
 * XY must be 256r bytes in length.  The value N must be a power of 2.
 */
static void
smix(uint8_t * B, size_t r, uint64_t N, uint8_t * V, uint8_t * XY)
{
	uint8_t * X = XY;
	uint8_t * Y = &XY[128 * r];
	uint64_t i;
	uint64_t j;

	/* 1: X <-- B */
	blkcpy(X, B, 128 * r);

	/* 2: for i = 0 to N - 1 do */
	for (i = 0; i < N; i++) {
		/* 3: V_i <-- X */
		blkcpy(&V[i * (128 * r)], X, 128 * r);

		/* 4: X <-- H(X) */
		blockmix_salsa8(X, Y, r);
	}

	/* 6: for i = 0 to N - 1 do */
	for (i = 0; i < N; i++) {
		/* 7: j <-- Integerify(X) mod N */
		j = integerify(X, r) & (N - 1);

		/* 8: X <-- H(X \xor V_j) */
		blkxor(X, &V[j * (128 * r)], 128 * r);
		blockmix_salsa8(X, Y, r);
	}

	/* 10: B' <-- X */
	blkcpy(B, X, 128 * r);
}

/**
 * crypto_scrypt(passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen):
 * Compute scrypt(passwd[0 .. passwdlen - 1], salt[0 .. saltlen - 1], N, r,
 * p, buflen) and write the result into buf.  The parameters r, p, and buflen
 * must satisfy r * p < 2^30 and buflen <= (2^32 - 1) * 32.  The parameter N
 * must be a power of 2.
 *
 * Return 0 on success; or -1 on error.
 */
int
crypto_scrypt(const uint8_t * passwd, size_t passwdlen,
    const uint8_t * salt, size_t saltlen, uint64_t N, uint32_t r, uint32_t p,
    uint8_t * buf, size_t buflen)
{
	uint8_t * B;
	uint8_t * V;
	uint8_t * XY;
	uint32_t i;

	/* Sanity-check parameters. */
#if SIZE_MAX > UINT32_MAX
	if (buflen > (((uint64_t)(1) << 32) - 1) * 32) {
		errno = EFBIG;
		goto err0;
	}
#endif
	if ((uint64_t)(r) * (uint64_t)(p) >= (1 << 30)) {
		errno = EFBIG;
		goto err0;
	}
	if (((N & (N - 1)) != 0) || (N == 0)) {
		errno = EINVAL;
		goto err0;
	}
	if ((r > SIZE_MAX / 128 / p) ||
#if SIZE_MAX / 256 <= UINT32_MAX
	    (r > SIZE_MAX / 256) ||
#endif
	    (N > SIZE_MAX / 128 / r)) {
		errno = ENOMEM;
		goto err0;
	}

	/* Allocate memory. */
	if ((B = (uint8_t *) malloc(128 * r * p)) == NULL)
		goto err0;
	if ((XY = (uint8_t *) malloc(256 * r)) == NULL)
		goto err1;
	if ((V = (uint8_t *) malloc(128 * r * N)) == NULL)
		goto err2;

	/* 1: (B_0 ... B_{p-1}) <-- PBKDF2(P, S, 1, p * MFLen) */
	PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, 1, B, p * 128 * r);

	/* 2: for i = 0 to p - 1 do */
	for (i = 0; i < p; i++) {
		/* 3: B_i <-- MF(B_i, N) */
		smix(&B[i * 128 * r], r, N, V, XY);
	}

	/* 5: DK <-- PBKDF2(P, B, 1, dkLen) */
	PBKDF2_SHA256(passwd, passwdlen, B, p * 128 * r, 1, buf, buflen);

	/* Free memory. */
	free(V);
	free(XY);
	free(B);

	/* Success! */
	return (0);

err2:
	free(XY);
err1:
	free(B);
err0:
	/* Failure! */
	return (-1);
}





