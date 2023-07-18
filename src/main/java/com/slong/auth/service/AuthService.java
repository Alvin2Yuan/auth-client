package com.slong.auth.service;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.date.DateUnit;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.io.FileUtil;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.symmetric.SymmetricCrypto;

import java.util.Date;

public class AuthService {
   public static String privateKey="q7M+XTfwAtNHfsjTS1f3tw==";

    private static SymmetricCrypto getSymmetricCrypto(){
        return SmUtil.sm4(Base64.decode(privateKey));
    }

    public static boolean validateAppKey(){
        SymmetricCrypto sm4=getSymmetricCrypto();
        String authContent=getAuthContent(sm4);
        boolean flag=true;
        if(authContent.contains("次数[")){
            String maxCountStr=authContent.substring(authContent.indexOf("次数[")+3,authContent.indexOf("]截止"));
            if(!authContent.contains("次数")){
                flag=false;
            }
            flag= Integer.parseInt(maxCountStr)>0;
        }
        if(!flag){
            return false;
        }
        String dateStr=authContent.substring(authContent.indexOf("==>>")+4);
        Date date= DateUtil.parse(dateStr);
         if(DateUtil.between(new Date(), date, DateUnit.MINUTE,false) > 0){
             if(authContent.contains("次数[")) {
                 updateRemainCount();
             }
             return true;
         }
         return false;
    }

    public static void updateRemainCount(){
        SymmetricCrypto sm4=getSymmetricCrypto();
        String authContent=getAuthContent(sm4);
        String maxCountStr=authContent.substring(authContent.indexOf("次数[")+3,authContent.indexOf("]截止"));

        int remainCount=Integer.parseInt(maxCountStr);
        remainCount=remainCount-1;
        authContent= authContent.replace("次数["+maxCountStr,"次数["+remainCount);
        String encryptHex = sm4.encryptBase64(authContent);
        String authFileStr=System.getProperty("user.dir")+"/auth.lic";
        FileUtil.writeUtf8String(encryptHex,authFileStr);
    }

    private static String getAuthContent(SymmetricCrypto sm4){

        String authFileStr=System.getProperty("user.dir")+"/auth.lic";
        if(!FileUtil.exist(authFileStr)){
            throw new RuntimeException("授权文件不存在,请联系管理员");
        }
        String authContent= FileUtil.readUtf8String(authFileStr);
        return sm4.decryptStr(authContent);
    }
}
