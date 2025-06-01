import tkinter as tk
import json
from tkinter import messagebox, scrolledtext, ttk
from crypto_algorithms import RSAHandler, DSAHandler, ECDSAHandler, SM2Handler, PerformanceTester
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import logging

# 配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s-%(levelname)s-%(message)s"
)
logger = logging.getLogger(__name__)


class CryptoExperimentGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("加密算法实验平台")
        self.root.geometry("1200x800")  # 增大窗口尺寸

        # 全局变量
        self.algorithm_var = tk.StringVar(value="RSA")
        self.handlers = {
            "RSA": RSAHandler(),
            "DSA": DSAHandler(),
            "ECDSA": ECDSAHandler(),
            "SM2": SM2Handler()
        }
        self.private_key = None
        self.public_key = None
        self.signature = None
        self.tester = PerformanceTester()

        # 创建界面组件
        self._create_tabs()

    def _create_tabs(self):
        """创建选项卡界面"""
        tab_control = ttk.Notebook(self.root)

        # 基础功能选项卡
        self.basic_frame = ttk.Frame(tab_control)
        tab_control.add(self.basic_frame, text="基础功能")
        self._create_basic_widgets()

        # 性能测试选项卡
        self.performance_frame = ttk.Frame(tab_control)
        tab_control.add(self.performance_frame, text="性能测试")
        self._create_performance_widgets()

        # 结果分析选项卡
        self.analysis_frame = ttk.Frame(tab_control)
        tab_control.add(self.analysis_frame, text="结果分析")
        self._create_analysis_widgets()

        tab_control.pack(expand=1, fill="both")

    def _create_basic_widgets(self):
        """创建基础功能界面"""
        # 消息输入区域
        ttk.Label(self.basic_frame, text="待签名/验证消息:").pack(pady=5)
        self.message_entry = ttk.Entry(self.basic_frame, width=60)
        self.message_entry.pack(pady=10)
        self.message_entry.insert(0, "国密SM2算法测试消息")  # 默认测试消息

        # 算法选择
        ttk.Label(self.basic_frame, text="选择加密算法:").pack(pady=5)
        ttk.OptionMenu(self.basic_frame, self.algorithm_var, "RSA", "DSA", "ECDSA", "SM2").pack(pady=10)

        # 密钥长度输入（仅RSA/DSA有效）
        self.key_size_frame = ttk.Frame(self.basic_frame)
        ttk.Label(self.key_size_frame, text="密钥长度（RSA/DSA专用）:").pack(side=tk.LEFT, padx=5)
        self.key_size_entry = ttk.Entry(self.key_size_frame, width=10)
        self.key_size_entry.pack(side=tk.LEFT, pady=5)
        self.key_size_entry.insert(0, "2048")
        self.key_size_frame.pack()

        # 功能按钮
        self.button_frame = ttk.Frame(self.basic_frame)
        ttk.Button(self.button_frame, text="生成密钥对", command=self.generate_keys).pack(side=tk.LEFT, padx=10,
                                                                                          pady=10)
        ttk.Button(self.button_frame, text="生成数字签名", command=self.sign_message).pack(side=tk.LEFT, padx=10,
                                                                                           pady=10)
        ttk.Button(self.button_frame, text="验证签名", command=self.verify_signature).pack(side=tk.LEFT, padx=10,
                                                                                           pady=10)
        self.button_frame.pack()

        # 结果显示区域
        self._create_result_display("私钥", "private_key", 5)
        self._create_result_display("公钥", "public_key", 5)
        self._create_result_display("签名结果", "signature", 5)

    def _create_performance_widgets(self):
        """创建性能测试界面"""
        frame = self.performance_frame

        # 测试配置
        config_frame = ttk.LabelFrame(frame, text="测试配置", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=10)

        # 算法选择
        ttk.Label(config_frame, text="测试算法:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.test_algorithms = {
            "RSA": tk.BooleanVar(value=True),
            "DSA": tk.BooleanVar(value=True),
            "ECDSA": tk.BooleanVar(value=True),
            "SM2": tk.BooleanVar(value=True)
        }
        col = 1
        for algo, var in self.test_algorithms.items():
            ttk.Checkbutton(config_frame, text=algo, variable=var).grid(row=0, column=col, padx=5, pady=5)
            col += 1

        # 迭代次数
        ttk.Label(config_frame, text="迭代次数:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.iterations_entry = ttk.Entry(config_frame, width=10)
        self.iterations_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        self.iterations_entry.insert(0, "50")

        # 消息大小
        ttk.Label(config_frame, text="消息大小(字节):").grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)
        self.msg_sizes_entry = ttk.Entry(config_frame, width=20)
        self.msg_sizes_entry.grid(row=1, column=3, sticky=tk.W, padx=5, pady=5)
        self.msg_sizes_entry.insert(0, "128,1024,8192")

        # 测试按钮
        ttk.Button(frame, text="运行性能测试", command=self.run_performance_test, style="Success.TButton").pack(pady=10)

        # 测试结果文本区域
        ttk.Label(frame, text="测试结果:").pack(pady=5)
        self.performance_text = scrolledtext.ScrolledText(frame, height=15, width=80)
        self.performance_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.performance_text.configure(font=("Consolas", 11))

        # 导出按钮
        ttk.Button(frame, text="导出结果到JSON", command=self.export_test_results).pack(pady=10)

    def _create_analysis_widgets(self):
        """创建结果分析界面"""
        frame = self.analysis_frame

        # 分析类型选择
        ttk.Label(frame, text="分析类型:").pack(pady=5)
        self.analysis_type = tk.StringVar(value="密钥生成时间")
        analysis_options = ["密钥生成时间", "签名生成时间", "签名验证时间", "签名长度"]
        ttk.OptionMenu(frame, self.analysis_type, *analysis_options).pack(pady=5)

        # 消息大小选择
        ttk.Label(frame, text="消息大小(字节):").pack(pady=5)
        self.analysis_msg_size = tk.StringVar(value="1024")
        msg_size_options = ["128", "1024", "8192"]
        ttk.OptionMenu(frame, self.analysis_msg_size, *msg_size_options).pack(pady=5)

        # 分析按钮
        ttk.Button(frame, text="生成分析图表", command=self.generate_analysis_chart).pack(pady=10)

        # 图表显示区域
        self.figure = plt.Figure(figsize=(8, 5), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.figure, frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _create_result_display(self, label_text, attr_name, height):
        """创建结果显示文本框"""
        ttk.Label(self.basic_frame, text=f"{label_text}:").pack(pady=3)
        text_widget = scrolledtext.ScrolledText(self.basic_frame, height=height, width=60, wrap=tk.WORD)
        text_widget.pack(pady=5, padx=10)
        setattr(self, f"{attr_name}_text", text_widget)

    # 基础功能方法（保持不变）
    def generate_keys(self):
        """生成密钥对"""
        try:
            algorithm = self.algorithm_var.get()
            handler = self.handlers[algorithm]
            key_size = self.key_size_entry.get() if algorithm in ["RSA", "DSA"] else None

            # 生成密钥
            if algorithm in ["RSA", "DSA"]:
                self.private_key, self.public_key = handler.generate_keys(int(key_size))
            else:
                self.private_key, self.public_key = handler.generate_keys()  # SM2/ECDSA无需长度参数

            # 显示密钥
            self._update_display("private_key", self.private_key)
            self._update_display("public_key", self.public_key)
            logger.info(f"{algorithm}密钥对生成成功")

        except Exception as e:
            messagebox.showerror("错误", f"密钥生成失败：{str(e)}")
            logger.error(f"密钥生成失败：{str(e)}", exc_info=True)

    def sign_message(self):
        """生成数字签名"""
        if not self.private_key:
            messagebox.showerror("错误", "请先生成密钥对")
            return

        message = self.message_entry.get().strip()
        if not message:
            messagebox.showerror("错误", "消息不能为空")
            return

        try:
            algorithm = self.algorithm_var.get()
            handler = self.handlers[algorithm]
            signature = handler.sign(self.private_key, message)

            # 处理SM2签名（直接存储JSON）
            self.signature = json.dumps(signature)
            self._update_display("signature", self.signature)
            logger.info(f"{algorithm}签名生成成功")

        except Exception as e:
            messagebox.showerror("错误", f"签名生成失败：{str(e)}")
            logger.error(f"{algorithm}签名失败：{str(e)}", exc_info=True)

    def verify_signature(self):
        """验证数字签名"""
        if not self.public_key:
            messagebox.showerror("错误", "请先生成密钥对")
            return

        signature_str = self.signature_text.get(1.0, tk.END).strip()
        if not signature_str:
            messagebox.showerror("错误", "签名结果为空")
            return

        try:
            algorithm = self.algorithm_var.get()
            handler = self.handlers[algorithm]
            message = self.message_entry.get().strip()
            signature_dict = json.loads(signature_str)

            result = handler.verify(self.public_key, message, signature_dict)
            messagebox.showinfo("验证结果", f"签名验证结果：{'通过' if result else '失败'}")
            logger.info(f"{algorithm}签名验证结果：{'通过' if result else '失败'}")

        except json.JSONDecodeError:
            messagebox.showerror("错误", "签名格式不正确（需为JSON格式）")
            logger.error(f"{algorithm}签名格式错误：无法解析JSON")
        except Exception as e:
            messagebox.showerror("错误", f"验证失败：{str(e)}")
            logger.error(f"{algorithm}签名验证失败：{str(e)}", exc_info=True)

    def _update_display(self, attr_name, content):
        """更新显示内容"""
        text_widget = getattr(self, f"{attr_name}_text")
        text_widget.delete(1.0, tk.END)
        if content:
            text_widget.insert(tk.END, content if isinstance(content, str) else str(content))

    # 性能测试方法
    def run_performance_test(self):
        """运行性能测试"""
        self.performance_text.delete(1.0, tk.END)
        self.performance_text.insert(tk.END, "正在准备性能测试...\n")
        self.root.update()

        try:
            # 获取配置
            selected_algorithms = [algo for algo, var in self.test_algorithms.items() if var.get()]
            iterations = int(self.iterations_entry.get())
            msg_sizes = [int(s.strip()) for s in self.msg_sizes_entry.get().split(',')]

            if not selected_algorithms:
                messagebox.showerror("错误", "请至少选择一种算法进行测试")
                return

            self.performance_text.insert(tk.END,
                                         f"开始性能测试：算法={selected_algorithms}, 迭代次数={iterations}, 消息大小={msg_sizes}\n\n")
            self.root.update()

            # 清空之前的结果
            self.tester.results = []

            # 运行测试
            for algorithm in selected_algorithms:
                self.performance_text.insert(tk.END, f"正在测试 {algorithm} 算法...\n")
                self.root.update()

                if algorithm in ["RSA", "DSA"]:
                    for key_size in [1024, 2048, 4096 if algorithm == "RSA" else 3072]:
                        self.tester.run_test(algorithm, key_size=key_size, message_sizes=msg_sizes,
                                             iterations=iterations)
                elif algorithm == "ECDSA":
                    for curve in ["P-256", "P-384"]:
                        self.tester.run_test(algorithm, curve=curve, message_sizes=msg_sizes, iterations=iterations)
                elif algorithm == "SM2":
                    for curve in ["SECP256K1", "SECP256R1", "SECP384R1"]:
                        self.tester.run_test(algorithm, curve=curve, message_sizes=msg_sizes, iterations=iterations)

            # 显示结果摘要
            summary = self.tester.get_summary()
            self.performance_text.insert(tk.END, "\n===== Test Result Summary =====\n")
            header = f"{'Algorithm':<10}{'Key Param':<14}{'Msg Size(B)':<12}{'KeyGen(ms)':<14}{'Sign(ms)':<10}{'Verify(ms)':<12}{'SigLen(B)':<10}\n"
            self.performance_text.insert(tk.END, header)
            self.performance_text.insert(tk.END, "-" * 82 + "\n")

            for result in summary:
                line = f"{result['algorithm']:<10}{str(result['key_param']):<14}{str(result['message_size']):<12}{result['avg_key_gen_time_ms']:<14.3f}{result['avg_sign_time_ms']:<10.3f}{result['avg_verify_time_ms']:<12.3f}{result['avg_signature_length_bytes']:<10.1f}\n"
                self.performance_text.insert(tk.END, line)

            messagebox.showinfo("测试完成", f"性能测试完成，共执行 {len(summary)} 个测试用例")

        except Exception as e:
            messagebox.showerror("错误", f"测试失败：{str(e)}")
            logger.error(f"性能测试失败：{str(e)}", exc_info=True)

    def export_test_results(self):
        """导出测试结果到JSON文件"""
        if not self.tester.results:
            messagebox.showwarning("警告", "没有可用的测试结果")
            return

        try:
            self.tester.export_results("signature_performance.json")
            messagebox.showinfo("成功", "测试结果已导出到 signature_performance.json")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败：{str(e)}")
            logger.error(f"导出测试结果失败：{str(e)}", exc_info=True)

    def generate_analysis_chart(self):
        """Generate analysis chart (with English labels)"""
        if not self.tester.results:
            messagebox.showwarning("Warning", "No available test results.")
            return

        try:
            analysis_type = self.analysis_type.get()
            msg_size = int(self.analysis_msg_size.get())

            # Clear the figure
            self.figure.clear()

            # Filter results for the selected message size
            filtered_results = [
                result for result in self.tester.get_summary()
                if result["message_size"] == msg_size
            ]

            if not filtered_results:
                messagebox.showwarning("Warning", f"No test results found for message size {msg_size} bytes.")
                return

            # Group by algorithm
            algorithms = sorted(list(set(r["algorithm"] for r in filtered_results)))
            key_params = sorted(list(set(r["key_param"] for r in filtered_results)))

            # Select data field and y-axis label based on analysis type
            if analysis_type == "密钥生成时间":
                data_field = "avg_key_gen_time_ms"
                y_label = "Average Key Generation Time (ms)"
                chart_title = f"Key Generation Time Comparison (Message Size: {msg_size} bytes)"
            elif analysis_type == "签名生成时间":
                data_field = "avg_sign_time_ms"
                y_label = "Average Signing Time (ms)"
                chart_title = f"Signing Time Comparison (Message Size: {msg_size} bytes)"
            elif analysis_type == "签名验证时间":
                data_field = "avg_verify_time_ms"
                y_label = "Average Verification Time (ms)"
                chart_title = f"Verification Time Comparison (Message Size: {msg_size} bytes)"
            else:  # 签名长度
                data_field = "avg_signature_length_bytes"
                y_label = "Average Signature Length (bytes)"
                chart_title = f"Signature Length Comparison (Message Size: {msg_size} bytes)"

            # Create the chart
            ax = self.figure.add_subplot(111)
            x = np.arange(len(algorithms))
            width = 0.8 / len(key_params)  # Bar width for each key param

            # Draw bars for each key param
            for i, param in enumerate(key_params):
                param_data = [
                    next((r[data_field] for r in filtered_results
                          if r["algorithm"] == algo and r["key_param"] == param), 0)
                    for algo in algorithms
                ]
                ax.bar(x + i * width - 0.4 + width / 2, param_data, width, label=str(param))

            # Set chart properties
            ax.set_ylabel(y_label)
            ax.set_title(chart_title)
            ax.set_xticks(x)
            ax.set_xticklabels(algorithms)
            ax.legend(title="Key Parameter", loc="best", fontsize=12, frameon=True)

            # Show the chart
            self.figure.tight_layout()
            self.canvas.draw()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate chart: {str(e)}")
            logger.error(f"Failed to generate analysis chart: {str(e)}", exc_info=True)


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoExperimentGUI(root)
    root.mainloop()