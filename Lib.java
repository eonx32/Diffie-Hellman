/*
 *  Some important functions for implementing
 *  Data Encryption standard
 *
 *  @author eonx_32
 *
 */

class Lib
{
    public static int[] stringToBinary(String s)
    {
        int[] t = new int[s.length()*8];
        
        for(int i=0;i<s.length();i++){
            
            char j = s.charAt(i);
            
            for(int k=7;k>=0;k--)
                t[i*8+7-k] = ((j&(1<<k))!=0)?1:0;
        }
        
        return t;
    }
    
    public static String binaryToString(int[] s)
    {
        StringBuilder t = new StringBuilder();
        
        for(int i=0;i<s.length;){
            
            char j = 0;
            
            for(int k=7;k>=0;i++,k--)
                if(s[i]!=0)
                    j+=(1<<k);
            t.append(j);
        }
        
        return t.toString();
    }
    
    public static String binaryToHex(int[] s)
    {
        char[] h = new char[]{'0','1','2','3','4','5','6',
            '7','8','9','A','B','C','D','E','F'};
        
        StringBuilder t = new StringBuilder();
        
        for(int i=0;i<s.length;){
            
            char j = 0;
            
            for(int k=3;k>=0;i++,k--)
                if(s[i]!=0)
                    j+=(1<<k);
            t.append(h[j]);
        }
        
        return t.toString();
    }
    
    public static int[] hexToBinary(String s)
    {
        char[] h = new char[]{'0','1','2','3','4','5','6',
            '7','8','9','A','B','C','D','E','F'};
        char[] x = new char[128];
        
        for(int i=0;i<16;i++)
            x[h[i]] = (char)i;
        
        int[] t = new int[s.length()*4];
        
        for(int i=0;i<s.length();i++){
            
            char j = (char)x[s.charAt(i)];
            
            for(int k=3;k>=0;k--)
                t[i*4+3-k] = ((j&(1<<k))!=0)?1:0;
        }
        
        return t;
    }
    
    public static String hexToString(String s)
    {
        return binaryToString(hexToBinary(s));
    }
    
    public static String stringToHex(String s)
    {
        return binaryToHex(stringToBinary(s));
    }
    
    public static int[] longToBinary(long n,int length)
    {
        int[] v = new int[length];
        for(int k=length-1;k>=0;k--)
            v[length-1-k] = ((n&(1<<k))!=0)?1:0;
        
        return v;
    }
    
    public static int[] padZeros(int[] v)
    {
        int n = v.length;
        int m = 0;
        int length = 0;
        
        if(n%64!=0){
            m = ((n+63)/64-1)*64 + n%64;
            length = ((n+63)/64)*64;
        }
        
        int[] u = new int[64];
        
        for(int i=0;i<n;i++)
            u[i] = v[i];
        for(int i=m;i<length;i++)
            u[i]=0;
        
        return u;
    }
    
    public static int[] rotateIntArray(int[] arr,int shift)
    {
        if(shift==0)    return arr;
        int j = arr[0];
        for(int i=0;i<arr.length-1;i++)
            arr[i] = arr[i+1];
        arr[arr.length-1] = j;
        
        return rotateIntArray(arr,shift-1);
    }
}
