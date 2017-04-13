/**
 *
 *  Data Encryption Standard to encrypt
 *  and decrypt messages using a 64-bit key
 *
 *  @author eonx_32
 *
 */

import java.util.*;

class DataEncryptionStandard
{
    private StringBuilder plaintext;
    private StringBuilder ciphertext;
    private String key;
    private int[] keyPerm1;
    private int[][] keyGen;
    private static final int[] PERM1;
    private static final int[] PERM2;
    private static final int[] IPPERM;
    private static final int[] IPINVERSEPERM;
    private static final int[] EPERM;
    private static final int[] PPERM;
    private static final int[][][] S;
    private static final boolean ENCRYPT = true;
    private static final boolean DECRYPT = false;
    
    static {
        //Initialization of all blocks
        
        //PC-1 block
        PERM1 = new int[]{57,49,41,33,25,17,9,1,
        58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,
        60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,
        30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};
        
        //PC-2 block
        PERM2 = new int[]{14,17,11,24,1,5,3,28,15,6,
        21,10,23,19,12,4,26,8,16,7,27,20,13,
        2,41,52,31,37,47,55,30,40,51,45,33,
        48,44,49,39,56,34,53,46,42,50,36,29,32};
        
        //IP block
        IPPERM = new int[]{58,50,42,34,26,18,10,2,60,52,44,
        36,28,20,12,4,62,54,46,38,30,22,14,6,64,
        56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,
        59,51,43,35,27,19,11,3,61,53,45,37,29,21,
        13,5,63,55,47,39,31,23,15,7};
        
        //IP inverse block
        IPINVERSEPERM = new int[]{40,8,48,16,56,24,64,32,39,7,47,
        15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,
        53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,
        19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25};
        
        //E block
        EPERM = new int[]{32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,
        13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,
        22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};
        
        //P Block
        PPERM = new int[]{16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
        2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
        
        S = new int[][][]{{{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
        {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
        {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
        {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
        },
        
        {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
        {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
        {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
        {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
        },
        
        {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
        {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
        {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
        {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
        },
        
        {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
        {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
        {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
        {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
        },
        
        {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
        {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
        {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
        {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
        },
        
        {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
        {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
        {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
        {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
        },
        
        {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
        {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
        {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
        {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
        },
        
        {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
        {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
        {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
        {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
        }};
    }
    
    DataEncryptionStandard(String key)
    {
        this.key = key;
        
        runPermCycle1();
        createKeys();
        runPermCycle2();
    }
    
    DataEncryptionStandard(long key)
    {
        this.key = Lib.binaryToString(Lib.longToBinary(key,64));
        
        runPermCycle1();
        createKeys();
        runPermCycle2();
    }
    
    public String encrypt(String plaintext)
    {
        //Encryption of the plaintext
        String message;
        int[] binaryMessage;
        
        StringBuilder ciphertext = new StringBuilder();
        
        //8 bytes of message is encoded in each step
        for(int i=0;i<plaintext.length();i+=8){
            if(i+8<=plaintext.length())
                message = plaintext.substring(i,i+8);
            else
                message = plaintext.substring(i,plaintext.length());
            
            binaryMessage = Lib.stringToBinary(message);
            
            //pad zeros
            binaryMessage = Lib.padZeros(binaryMessage);
            
            message = Lib.binaryToString(encodeMessage(binaryMessage,ENCRYPT));
            ciphertext.append(message);
        }
        
        return ciphertext.toString();
    }
    
    public String decrypt(String ciphertext)
    {
        //Decryption of plaintextString message;
        String message;
        int[] binaryMessage;
        StringBuilder plaintext = new StringBuilder();
        
        
        //8 bytes of message is encoded in each step
        for(int i=0;i<ciphertext.length();i+=8){
            if(i+8<=ciphertext.length())
                message = ciphertext.substring(i,i+8);
            else
                message = ciphertext.substring(i,ciphertext.length());
            
            binaryMessage = Lib.stringToBinary(message);
            
            //pad zeros
            binaryMessage = Lib.padZeros(binaryMessage);
            
            message = Lib.binaryToString(encodeMessage(binaryMessage,DECRYPT));
            plaintext.append(message);
        }
        
        return plaintext.toString();
    }
    
    private void runPermCycle1()
    {
        //Permutation of original key
        int[] keyOld = Lib.stringToBinary(key);
        
        int[] keyNew = new int[56];
        
        keyOld = Lib.padZeros(keyOld);
        
        for(int i=0;i<56;i++)
            keyNew[i] = keyOld[PERM1[i]-1];
        
        keyPerm1 = keyNew;
    }
    
    private void createKeys()
    {
        //Creation of the 16 keys by shifting the initial keys
        int[] c,d;
        
        c = Arrays.copyOfRange(keyPerm1,0,28);
        d = Arrays.copyOfRange(keyPerm1,28,keyPerm1.length);
        
        keyGen = new int[16][];
        //Apply shift and generate each 16 keys
        for(int i=0;i<16;i++){
            int shift = 2;
            if(i<2||i==8||i==15) shift--;
            c = Lib.rotateIntArray(c,shift);
            d = Lib.rotateIntArray(d,shift);
            
            keyGen[i] = new int[56];
            for(int j = 0;j<c.length;j++)
                keyGen[i][j] = c[j];
            for(int j = 0;j<d.length;j++)
                keyGen[i][j+28] = d[j];
        }
        
    }
    
    private void runPermCycle2()
    {
        //Permutaion of the 16 keys generated using shift
        int[] keyNew = new int[48];
        
        for(int i=0;i<16;i++){
            for(int j=0;j<48;j++)
                keyNew[j] = keyGen[i][PERM2[j]-1];
            keyGen[i] = Arrays.copyOf(keyNew,keyNew.length);
        }
    }
    
    private int[] fFunction(int[] R,int keyIndex)
    {
        //function to calculate the R for each iteration
        int[] E = new int[48];
        int[] F = new int[32];
        
        //Generate E(R) using bit selection table
        //R = K^E(R)
        for(int i=0;i<48;i++)
            E[i] = keyGen[keyIndex][i]^R[EPERM[i]-1];
        
        //Convert each 6 blocks of bit into 4 blocks using Sbox
        for(int i=0;i<48;i+=6){
            int x = (E[i]<<1)+E[i+5];
            int y = 0;
            for(int j=0;j<4;j++)
                y = (y<<1)+E[i+j+1];
            
            int[] v = Lib.longToBinary(S[(i+1)/6][x][y],4);
            
            for(int j=0;j<v.length;j++)
                F[(i/6)*4+j] = v[j];
        }
        
        int[] P = new int[32];
        
        //Permute the generate R using P block
        for(int i=0;i<32;i++)
            P[i] = F[PPERM[i]-1];
        
        return P;
    }
    
    private int[] encodeMessage(int[] message,boolean mode)
    {
        //Encode each 64 bits of message
        int[] ip = new int[64];
        int[] ipInverse = new int[64];
        
        //Permute the message using IP block
        for(int i=0;i<64;i++)
            ip[i] = message[IPPERM[i]-1];
        
        int[] L0,R0,L,R;
        
        //Break the message IP in two parts
        L0 = Arrays.copyOfRange(ip,0,32);
        R0 = Arrays.copyOfRange(ip,32,ip.length);
        
        for(int i=0;i<16;i++){
            L = Arrays.copyOf(R0,R0.length);
            if(mode == ENCRYPT)
                R = fFunction(R0,i);
            else R=fFunction(R0,16-i-1);
            
            for(int j=0;j<32;j++)
                R[j] = R[j]^L0[j];
            
            L0 = Arrays.copyOf(L,L.length);
            R0 = Arrays.copyOf(R,R.length);
        }
        
        //IP = R0.L0
        ip = new int[64];
        for(int i=0;i<32;i++)
            ip[i] = R0[i];
        for(int i=0;i<L0.length;i++)
            ip[i+32] = L0[i];
        
        //Generate IP inverse using IPinverse permutation block
        for(int i=0;i<64;i++)
            ipInverse[i] = ip[IPINVERSEPERM[i]-1];
        
        return ipInverse;
    }
}
