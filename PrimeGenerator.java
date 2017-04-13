/**
 *
 *  Generation of 64 bit prime number
 *  and a primitive root modulo n
 *
 *  @author eonx_32
 */

import java.util.*;
import java.math.*;

class PrimeGenerator
{
    //A method for Fast modular exponentiation
    public static long powerMod(long n,long p,long mod)
    {
        //Since mod may be > 10^15 so BigInteger is used
        //to prevent overflow
        BigInteger x = new BigInteger(""+1);
        BigInteger y = new BigInteger(""+n);
        BigInteger z = new BigInteger(""+mod);
        
        while(p!=0){
            if((p&1)==1)    x = x.multiply(y).mod(z);//x = (x*n)%mod
            y = y.multiply(y).mod(z);//n = (n*n)%mod
            p>>=1;
        }
        
        return x.longValue();
    }
    
    //Rabin-Miller for primality test
    public static boolean rabinMiller(long n,long k)
    {
        Random rand = new Random();
        long s = 0;
        long d = n-1;
        
        while((d&1)==0){
            d/=2;
            s++;
        }
        
        while(k>0){
            k--;
            long b = rand.nextLong();
            if(b<0) b*=-1;
            long a = b%(n-4)+2;
            long x = powerMod(a,d,n);
            
            if(x==1||x==n-1)
                continue;
            
            //Big Integer to prevent Overflow
            for(int i=1;i<s;i++){
                BigInteger p = new BigInteger(""+x);
                BigInteger q = new BigInteger(""+n);
                
                //x=(x*x)%n
                p = p.multiply(p).mod(q);
                x = p.longValue();
                
                if(x==1)    return false;//Compositeness
                if(x==n-1)  break;
            }
            if(x==n-1)  continue;
            return false;//Compositeness
        }
        
        return true;//Probably prime
    }
    
    //Check for the primality test
    public static boolean isPrime(long n)
    {
        int[] lowPrimes = new int[]{3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997};
        
        if(n>=3){
            if((n&1)!=0){
                for(int p : lowPrimes){
                    if(n==p)    return true;//prime
                    if(n%p==0)  return false;//composite
                }
                return rabinMiller(n,30);//probably prime
            }
        }
        
        return false;
    }
    
    //Return a prime randomly generated with some randomization
    public static long getPrime()
    {
        Random rand = new Random(System.currentTimeMillis());
        long n;
        do{
            long mod = rand.nextInt(63);
            mod = 1L<<mod;
            n= rand.nextLong();
            if(n<0) n*=-1;
            n%=mod;
        }while(!isPrime(n));
        
        return n;
    }
    
    //Trial Divison method to find divisors
    static ArrayList<Long> getDivisors(long n)
    {
        ArrayList<Long> divisors = new ArrayList<Long>();
        
        divisors.add(2L);
        while(n%2==0)   n/=2;
        for(long d=3;d<=n;d+=2){
            if(n%d==0){
                divisors.add(d);
                while(n%d==0)
                    n/=d;
            }
        }
        
        return divisors;
    }
    
    //Generate Primitive Root modulo n
    public static long generatePrimitiveRoot(long n)
    {
        ArrayList<Long> divisors = getDivisors(n-1);
        Random rand = new Random(System.currentTimeMillis());
        long x = 1;
        long a = 2;
        
        while(true){
            a = rand.nextLong();
            if(a<0) a*=-1;
            a%=(n-1)+1;
            for(long divisor:divisors){
                x = powerMod(a,n/divisor,n);
                
                if(x==1) break;
            }
            if(x!=1)    return a;
        }
    }
    
    public static void main(String[] args)
    {
        long x = getPrime();
        System.out.print(x);
        System.out.println(" "+generatePrimitiveRoot(x));
    }
}
