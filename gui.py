import tkinter as tk
import json
from tkinter import messagebox
from crypto_algorithms import RSAHandler,DSAHandler,ECDSAHandler,SM2Handler
import logging
#配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s-%(levelname)s-%(message)s"
)
logger=logging.getLogger(__name__)

class CryptoExperimentGUI:#创建用户交互界面
    def __init__(self,root):
        self.root=root
        self.root.title("加密算法实验平台")

        self.algorithm_var=tk.StringVar()
        self.algorithm_var.set("RSA")

        self.message_entry=tk.Entry(root,width=50)
        self.message_entry.pack(pady=10)

        self.algorithm_menu=tk.OptionMenu(root,self.algorithm_var,"RSA","DSA","ECDSA","SM2")
        self.algorithm_menu.pack(pady=10)

        self.key_size_label=tk.Label(root,text="密钥长度")
        self.key_size_label.pack(pady=5)
        self.key_size_entry=tk.Entry(root,width=10)
        self.key_size_entry.insert(0,"2048")
        self.key_size_entry.pack(pady=5)


        self.generate_keys_button=tk.Button(root,text="生成密钥",command=self.generate_keys)
        self.generate_keys_button.pack(pady=10)

        self.sign_button = tk.Button(root, text="生成签名", command=self.sign_message)
        self.sign_button.pack(pady=10)

        self.verify_button = tk.Button(root, text="验证签名", command=self.verify_signature)
        self.verify_button.pack(pady=10)

        self.private_key_label=tk.Label(root,text="私钥：")
        self.private_key_label.pack(pady=5)
        self.private_key_text=tk.Text(root,height=5,width=50)
        self.private_key_text.pack(pady=5)

        self.public_key_label=tk.Label(root,text="公钥：")
        self.public_key_label.pack(pady=5)
        self.public_key_text=tk.Text(root,height=5,width=50)
        self.public_key_text.pack(pady=5)

        self.signature_label=tk.Label(root,text="签名：")
        self.signature_label.pack(pady=5)
        self.signature_text=tk.Text(root,height=5,width=50)
        self.signature_text.pack(pady=5)

        self.handlers={
            "RSA":RSAHandler(),
            "DSA":DSAHandler(),
            "ECDSA":ECDSAHandler(),
            "SM2":SM2Handler()
        }

        self.private_key=None
        self.public_key=None
        self.signature=None

    def generate_keys(self):
        key_size=self.key_size_entry.get()
        try:
            algorithm=self.algorithm_var.get()
            handler=self.handlers[algorithm]

            #依据算法类型传递参数
            if algorithm in ["RSA","DSA"]:
                key_size=int(key_size)
                self.private_key, self.public_key = handler.generate_keys(key_size=key_size)
            else:
                self.private_key, self.public_key = handler.generate_keys()

            #显示统一的密钥逻辑
            self.public_key_text.delete(1.0,tk.END)
            self.public_key_text.delete(1.0,tk.END)


            if algorithm =="SM2":
                self.private_key_text.insert(tk.END,self.private_key.upper())
                self.public_key_text.insert(tk.END,f"04{self.public_key[:64].upper()}\n{self.public_key[64:].upper()}")
            else:
                self.private_key_text.insert(tk.END, self.private_key.decode())
                self.public_key_text.insert(tk.END,self.public_key.decode())
            logger.info("密钥生成成功")
        except ValueError:
            messagebox.showerror("错误","密钥长度输入不正确，请输入一个整数")
        except Exception as e:
            messagebox.showerror("错误",f"密钥生成失败：{str(e)}")



    def sign_message(self):
        if self.private_key is None:
            messagebox.showerror("错误","请先生成密钥")
            return
        algorithm=self.algorithm_var.get()
        handler=self.handlers[algorithm]
        message=self.message_entry.get()
        try:
            self.signature=handler.sign(self.private_key,message)
            self.signature_text.delete(1.0,tk.END)
            self.signature_text.insert(tk.END,json.dumps(self.signature))
            logger.info("签名生成成功")
        except Exception as e:
            messagebox.showerror("错误",f"生成签名时出现问题：{str(e)}")


    def verify_signature(self):
        if self.public_key is None:
            messagebox.showerror("错误","请先生成密钥")
            return

        algorithm=self.algorithm_var.get()
        handler=self.handlers[algorithm]
        message=self.message_entry.get()
        signature_str=self.signature_text.get(1.0,tk.END).strip()

        if not signature_str:
            messagebox.showerror("错误","签名不能为空")
            return

        try:
            #使用JSON解析签名数据
            signature_dict=json.loads(signature_str)
            result = handler.verify(self.public_key, message, signature_dict)
            messagebox.showinfo("验证结果", f"签名验证结果：{'通过' if result else '失败'}")
        except json.JSONDecodeError:
            messagebox.showerror("错误","签名格式不正确（需合法JSON格式）")
        except Exception as e:
            messagebox.showerror("错误", f"验证过程出错:{str(e)}")


if __name__=="__main__":
    root=tk.Tk()
    app=CryptoExperimentGUI(root)
    root.mainloop()


