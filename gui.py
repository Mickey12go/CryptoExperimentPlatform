import tkinter as tk
from tkinter import messagebox
from crypto_algorithms import RSAHandler,DSAHandler,ECDSAHandler,SM2Handler

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
        algorithm=self.algorithm_var.get()
        handler=self.handlers[algorithm]
        self.private_key,self.public_key=handler.generate_keys()
        self.private_key_text.delete(1.0,tk.END)
        self.private_key_text.insert(tk.END,self.private_key)
        self.public_key_text.delete(1.0,tk.END)
        self.public_key_text.insert(tk.END,self.public_key)


    def sign_message(self):
        if self.private_key is None:
            messagebox.showerror("错误","请先生成密钥")
            return
        algorithm=self.algorithm_var.get()
        handler=self.handlers[algorithm]
        message=self.message_entry.get()
        self.signature=handler.sign(self.private_key,message)
        self.signature_text.delete(1.0,tk.END)
        self.signature_text.insert(tk.END,self.signature.hex() if isinstance(self.signature,bytes)else self.signature)


    def verify_signature(self):
        if self.public_key is None or self.signature is None:
            messagebox.showerror("错误","请先生成密钥和签名")
            return
        algorithm=self.algorithm_var.get()
        handler=self.handlers[algorithm]
        message=self.message_entry.get()
        signature_str=self.signature_text.get(1.0,tk.END).strip()
        if signature_str:
            try:
                self.signature = bytes.fromhex(signature_str)
                result=handler.verify(self.public_key,message,self.signature)
                messagebox.showinfo("验证结果",f"签名验证结果：{'通过'if result else'失败'}")
            except ValueError:
                messagebox.showerror("错误","签名格式不正确")
        else:
            messagebox.showerror("错误","签名不能为空")



if __name__=="__main__":
    root=tk.Tk()
    app=CryptoExperimentGUI(root)
    root.mainloop()


