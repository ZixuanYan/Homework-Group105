#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <chrono>
#include <thread>

using namespace std;

typedef unsigned int uint;
#define thread_num 4
static uint T[64];

static const enum
{
	A = 0, B = 1, C = 2, D = 3,
	E = 4, F = 5, G = 6, H = 7
};

static const uint IV[8] =
{
	0x7380166F,	0x4914B2B9,
	0x172442D7,	0xDA8A0600,
	0xA96F30BC,	0x163138AA,
	0xE38DEE4D,	0xB0FB0E4E,
};

void printer(unsigned char* buf, int len)
{
	for (int i = 0; i < len; i++)
		printf("%02x", buf[i]);
	printf("\n\n");
	return;
}

static void _T()
{
	for (int i = 0; i < 16; i++)
		T[i] = 0x79CC4519;
	for (int i = 16; i < 64; i++)
		T[i] = 0x7A879D8A;
}

static uint leftshift(const uint s, const uint len)
{
	return ((s << len) & 0xFFFFFFFF | ((s & 0xFFFFFFFF) >> (32 - len)));
}

static uint FF(const uint s1, const uint s2, const uint s3, const uint i)
{
	if (0 <= i && i <= 15)
		return (s1 ^ s2 ^ s3);
	else if (16 <= i && i < 64)
		return ((s1 & s2) | (s1 & s3) | (s2 & s3));
	return 0;
}

static uint GG(const uint s1, const uint s2, const uint s3, const uint i)
{
	if (0 <= i && i <= 15)
		return (s1 ^ s2 ^ s3);
	else if (16 <= i && i < 64)
		return ((s1 & s2) | (~s1 & s3));
	return 0;
}

static uint P0(const uint s)
{
	return (s ^ (leftshift(s, 9)) ^ (leftshift(s, 17)));
}

static uint P1(const uint s)
{
	return (s ^ (leftshift(s, 15)) ^ (leftshift(s, 23)));
}

static uint compress(unsigned char* m, uint hash[8])
{
	uint w68[68];
	uint w64[64];

	for (int i = 0; i < 16; i++)
		w68[i] = ((uint)m[i * 4 + 0] << 24) & 0xFF000000 | ((uint)m[i * 4 + 1] << 16) & 0x00FF0000 | ((uint)m[i * 4 + 2] << 8) & 0x0000FF00 | ((uint)m[i * 4 + 3] << 0) & 0x000000FF;

	for (int i = 16; i < 68; i++)
		w68[i] = P1(w68[i - 16] ^ w68[i - 9] ^ (leftshift(w68[i - 3], 15))) ^ (leftshift(w68[i - 13], 7)) ^ w68[i - 6];

	for (int i = 0; i < 64; i++)
		w64[i] = w68[i] ^ w68[i + 4];

	uint iter[8] = { 0 };
	for (int i = 0; i < 8; i++)
		iter[i] = hash[i];

	uint SS1 = 0, SS2 = 0, TT1 = 0, TT2 = 0;
	int power = pow(2, 32);
	for (int i = 0; i < 64; i++)
	{
		SS1 = leftshift((leftshift(iter[A], 12) + iter[E] + leftshift(T[i], i % 32)) % power, 7);
		SS2 = SS1 ^ (leftshift(iter[A], 12));
		TT1 = (FF(iter[A], iter[B], iter[C], i) + iter[D] + SS2 + w64[i]) % power;
		TT2 = (GG(iter[E], iter[F], iter[G], i) + iter[H] + SS1 + w68[i]) % power;
		iter[D] = iter[C];
		iter[C] = leftshift(iter[B], 9);
		iter[B] = iter[A];
		iter[A] = TT1;
		iter[H] = iter[G];
		iter[G] = leftshift(iter[F], 19);
		iter[F] = iter[E];
		iter[E] = P0(TT2);
	}

	for (int i = 0; i < 8; i++)
		hash[i] = iter[i] ^ hash[i];

	return 0;
}

void SM3(unsigned char* message, uint len, unsigned char* Hash)
{
	_T();

	//padding
	uint num = (len + 1 + 8 + 64) / 64;
	unsigned char* buffer = (unsigned char*)malloc(num * 64);
	memset(buffer, 0, num * 64);
	memcpy(buffer, message, len);
	buffer[len] = 0x80;

	int i = 0;
	for (i = 0; i < 8; i++)
		buffer[num * 64 - i - 1] = ((unsigned long long)(len * 8) >> (i * 8)) & 0xFF;

	uint nHash[8];
	for (int i = 0; i < 8; i++)
		nHash[i] = IV[i];

	for (i = 0; i < num; i++)
		compress(&buffer[i * 64], nHash);

	free(buffer);

	for (i = 0; i < 8; i++)
	{
		Hash[i * 4 + 0] = (unsigned char)((nHash[i] >> 24) & 0xFF);
		Hash[i * 4 + 1] = (unsigned char)((nHash[i] >> 16) & 0xFF);
		Hash[i * 4 + 2] = (unsigned char)((nHash[i] >> 8) & 0xFF);
		Hash[i * 4 + 3] = (unsigned char)((nHash[i] >> 0) & 0xFF);
	}

}
// 4线程的函数，每个线程计算250次SM3
void Thread4(unsigned char* message, uint len, unsigned char* Hash)
{
	for (int i = 0; i < 250; i++)
		SM3(message, len, Hash);
}
// 调用4个线程并行计算SM3
void thread4(unsigned char* message, uint len, unsigned char* Hash)
{
	thread* threads = new thread[thread_num];
	int i = 0;
	for (i = 0; i < thread_num; i++)
		threads[i] = thread(Thread4, ref(message), len, Hash);
	for (i = 0; i < thread_num; i++)
		threads[i].join();
}
// 8线程的函数，每个线程计算125次SM3
void Thread8(unsigned char* message, uint len, unsigned char* Hash)
{
	for (int i = 0; i < 125; i++)
		SM3(message, len, Hash);
}
// 调用8个线程并行计算SM3

void thread8(unsigned char* message, uint len, unsigned char* Hash)
{
	thread* threads = new thread[thread_num * 2];
	int i = 0;
	for (i = 0; i < thread_num * 2; i++)
		threads[i] = thread(Thread4, ref(message), len, Hash);
	for (i = 0; i < thread_num * 2; i++)
		threads[i].join();
}

int main()
{
	unsigned char message[256] = "SDUYZX";
	unsigned char digest[256] = "";
	uint len = strlen((const char*)message);

	auto start = std::chrono::steady_clock::now();
	for (int i = 0; i < 1000; i++)
		SM3(message, len, digest);
	auto end = std::chrono::steady_clock::now();
	double t = std::chrono::duration<double, std::milli>(end - start).count();
	printf("单线程运行1000次时间：%.2f ms\n", t);

	start = std::chrono::steady_clock::now();
	thread4(message, len, digest);
	end = std::chrono::steady_clock::now();
	t = std::chrono::duration<double, std::milli>(end - start).count();
	printf("四线程运行1000次时间：%.2f ms\n", t);

	start = std::chrono::steady_clock::now();
	thread8(message, len, digest);
	end = std::chrono::steady_clock::now();
	t = std::chrono::duration<double, std::milli>(end - start).count();
	printf("八线程运行1000次时间：%.2f ms\n\n", t);

	printf("明文:\n%s\n\n", message);
	printf("密文:\n");
	printer(digest, 32);



	return 0;
}

