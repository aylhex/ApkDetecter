ApkDetecter   
+++++++++++++++++++++++++++++++++++++++++++   
运行环境：  
1、python 版本 < 3.0  
2、安装pyqt组件   
3、双击ApkDetecter.pyw可直接运行   
+++++++++++++++++++++++++++++++++++++++++++   

Android Apk查壳工具源代码   
主要功能：   
1、检测DEX文件是否加固及加固厂商   
2、检测APK的基本信息：     
   APKMD5值，APK包名，APK版本，签名信息等    
3、DEX文件的字节信息   

如果想增加新的apk加固检测方法       
可在CheckProtect类中self.protectflag_dict添加检测点   
