#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#define KeeLoq_NLF 0x3A5C742E
#define bit(x,n) (((x)>>(n))&1)
#define g5(x,a,b,c,d,e) (bit(x,a)+bit(x,b)*2+bit(x,c)*4+bit(x,d)*8+bit(x,e)*16)
typedef unsigned long int uint32_t;
typedef unsigned long long int uint64_t;
typedef unsigned long u32;
typedef unsigned long long u64;
uint64_t key=0x7D093B66B31C374A;
uint32_t  KeeLoq_Encrypt (const uint32_t data, const uint64_t key){
  uint32_t  x = data, r;
  for (r = 0; r < 528; r++){
    x = (x>>1)^((bit(x,0)^bit(x,16)^(uint32_t)bit(key,r&63)^bit(KeeLoq_NLF,g5(x,1,9,20,26,31)))<<31);
  }
  return x;
}
uint32_t  KeeLoq_Decrypt (const uint32_t data, const uint64_t key)
{
  uint32_t   x = data, r;
  for (r = 0; r < 528; r++){
    x = (x<<1)^bit(x,31)^bit(x,15)^(uint32_t)bit(key,(15-r)&63)^bit(KeeLoq_NLF,g5(x,0,8,19,25,30));
  }
  return x;
}
int main(int argc,char * argv[]){
unsigned long data = strtoul(argv[1],NULL,16);
//printf("%lu\n",data);
//uint32_t datae=KeeLoq_Encrypt(data,key);
//printf("%lX",datae);
//long unsigned int datad=KeeLoq_Decrypt(data,key);
key=0x7D093B66B31C374A;
long unsigned int datad;
datad=KeeLoq_Decrypt(data,key);
datad=datad<<32;
datad=datad>>32;

printf("%lX",datad);
printf("\n");
//printf("\n");
return 0; 
}
