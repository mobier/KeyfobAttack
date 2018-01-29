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
uint64_t key;
unsigned long int  a[40]={

};
uint32_t  KeeLoq_Encrypt (const uint32_t data, const uint64_t key){
uint32_t  x = data, r;
for (r = 0; r < 528; r++){
    x = (x>>1)^((bit(x,0)^bit(x,16)^(uint32_t)bit(key,r&63)^bit(KeeLoq_NLF,g5(x,1,9,20,26,31)))<<31);
  }
  return x;
}
uint32_t  KeeLoq_Decrypt (const uint32_t data, const uint64_t key){
  uint32_t x = data, r;
  for (r = 0; r < 528; r++){
    x = (x<<1)^bit(x,31)^bit(x,15)^(uint32_t)bit(key,(15-r)&63)^bit(KeeLoq_NLF,g5(x,0,8,19,25,30));
  }
  return x;
}
int main(int argc,char * argv[]){
//unsigned long data = strtoul(argv[1],NULL,16);
unsigned long sn = strtoul(argv[1],NULL,16);
//char * Action =argv[2];
long unsigned int datad,Msb,Lsb,Key_data;
key=0x0000000000000000;//厂商KEY
Msb =KeeLoq_Decrypt(sn+0x60000000,key);
Lsb =KeeLoq_Decrypt(sn+0x20000000,key);
Msb=Msb <<32;
Lsb=Lsb <<32;
Lsb=Lsb >>32;
Key_data=Msb+Lsb;
printf("%lX",Key_data);
printf("\n");

//long unsigned int gsn=datad;
//gsn=gsn<<8;gsn=gsn>>8;gsn=gsn>>16;gsn=gsn<<16;
//if (gsn ==sn){
return 0; 
}

