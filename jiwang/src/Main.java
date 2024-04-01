import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.util.zip.CRC32;

public class Main {
    //被选中的网卡下标
    static int Index = 0;
    static JFrame frame;
    static JPanel mainPanel;
    public static void main(String[] args) {

        // 获取网卡列表
        NetworkInterface[] devices = JpcapCaptor.getDeviceList();
        // 打印网卡信息
        System.out.println("可用网卡:");
        for (int i = 0; i < devices.length; i++) {
            System.out.println(i + ": " + devices[i].name + " (" + devices[i].description + ")");
            NetworkInterfaceAddress[] addresses = devices[i].addresses;
            if (addresses != null && addresses.length > 0) {
                    System.out.println(addresses[1].address.toString() + "\n");
            }
        }

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    JpcapCaptor captor = JpcapCaptor.openDevice(devices[1], 65535, true, 20);
                    createAndShowGUI(devices,captor);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });

    }

    private static void createAndShowGUI(NetworkInterface[] devices,JpcapCaptor captor) {
        frame = new JFrame("TCP数据包分析器");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(1500, 800);

        // 创建主面板
        mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        frame.getContentPane().add(mainPanel, BorderLayout.CENTER);

        // 创建选择网卡按钮和显示网卡标签并添加监听器
        JButton jButton = new JButton("选择网卡");
        jButton.setBounds(750, 50, 200, 30);
        JLabel selectedInterfaceLabel = new JLabel();

        //监听事件
        jButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 弹出选择网卡对话框
                String[] interfaceNames = new String[devices.length];
                for (int i = 0; i < devices.length; i++) {
                    interfaceNames[i] = devices[i].name;
                }
                String selectedInterface = (String) JOptionPane.showInputDialog(frame,
                        "请选择一个网卡：", "选择网卡", JOptionPane.PLAIN_MESSAGE, null, interfaceNames, interfaceNames[0]);
                // 如果用户选择了网卡，则更新按钮下方的标签
                if (selectedInterface != null) {
                    // 寻找选择的网卡在interfaceNames数组中的下标
                    for (int i = 0; i < interfaceNames.length; i++) {
                        if (interfaceNames[i].equals(selectedInterface)) {
                            Index = i;
                            break;
                        }
                    }
                    //显示选择的网卡名
                    NetworkInterfaceAddress[] addresses = devices[Index].addresses;
                    selectedInterfaceLabel.setText("已选择的网卡： "+addresses[1].address.toString()+"\n");
                }
            }
        });
        // 将按钮和标签添加到主面板
        mainPanel.add(jButton);
        mainPanel.add(selectedInterfaceLabel);

        // 开始捕获
        JButton jButton2 = new JButton("开始捕获");
        jButton2.setBounds(750, 100, 200, 30);
        NetworkInterface selectedDevice = devices[Index];
        jButton2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    // 打开选定的网卡进行数据包捕获
//                    只能捕捉到最开始的建立连接包
//                    JpcapCaptor captor = JpcapCaptor.openDevice(selectedDevice, 65535, true, 20);
                    // 开始捕获数据包
                    int i = 1;
                    while (true) {
                        Packet packet = captor.getPacket();
//                        System.out.println(packet);
//                        System.out.println(1);
                        if (packet instanceof TCPPacket) {

                            System.out.println(2);
                            // 对TCP数据包进行简要分析
                            TCPPacket tcpPacket = (TCPPacket) packet;


                            JTable table = new JTable(13, 2);
                            // 设置第一列的固定文本
                            table.setValueAt("第"+(i++)+"个数据包", 0, 0);
                            table.setValueAt("源端口", 1, 0);
                            table.setValueAt("目的端口", 2, 0);
                            table.setValueAt("序号", 3, 0);
                            table.setValueAt("确认号", 4, 0);
                            table.setValueAt("数据偏移", 5, 0);
                            table.setValueAt("窗口大小", 6, 0);
                            table.setValueAt("紧急指针", 7, 0);
                            table.setValueAt("选项", 8, 0);
                            table.setValueAt("协议", 9, 0);
                            table.setValueAt("数据", 10, 0);
                            table.setValueAt("校验和", 11, 0);
                            table.setValueAt("控制位", 12, 0);

                            table.setValueAt(tcpPacket.src_port, 1, 1);
                            table.setValueAt(tcpPacket.dst_port, 2, 1);
                            table.setValueAt(tcpPacket.sequence, 3, 1);
                            table.setValueAt(tcpPacket.ack_num, 4, 1);
                            table.setValueAt(calculateDataOffset(tcpPacket), 5, 1);
                            table.setValueAt(tcpPacket.window, 6, 1);
                            table.setValueAt(showurgent(tcpPacket.urgent_pointer), 7, 1);
                            table.setValueAt(tcpPacket.options, 8, 1);
                            table.setValueAt(panProtorl(tcpPacket.protocol), 9, 1);
                            table.setValueAt(tcpPacket.data, 10, 1);
                            table.setValueAt(calculateChecksum(tcpPacket), 11, 1);
                            String str = "";
                            if(tcpPacket.urg){
                                str += "URG Flag: 该报文有紧急数据  ";
                            }
                            if(tcpPacket.ack){
                                str += "ACK Flag: 确认字段有效   ";
                            }else{
                                str += "ACK Flag: 确认字段无效   ";
                            }
                            if(tcpPacket.psh){
                                str += "PSH Flag: 立即推送   ";
                            }
                            if (tcpPacket.rst){
                                str += "RST Flag: 重置连接  ";
                            }
                            if (tcpPacket.syn){
                                str += "SYN Flag: 同步连接  ";
                            }
                            if (tcpPacket.fin){
                                str += "FIN Flag: 结束连接  ";
                            }
                            table.setValueAt(str, 12, 1);
                            // 将表格添加到面板中
                            mainPanel.add(table);
                            showInConsole(tcpPacket);
                            break;
                        }
                    }
                } catch (Exception exception) {
                    exception.printStackTrace();
                }
            }

        });
        mainPanel.add(jButton2);
        // 添加主面板到窗口中
//        frame.add(mainPanel);
        frame.setLocationRelativeTo(null);
        // 设置窗口可见
        frame.setVisible(true);
    }
    public static String showurgent(short urgent){
        if (urgent == 0){
            return "无紧急数据";
        }else{
            return "有"+urgent+"字节的紧急数据";
        }
    }
public static String panProtorl(short protocol){
    switch (protocol){
        case 1:
            return "ICMP协议";
        case 2:
            return "IGMP协议";
        case 4:
            return "IP协议";
        case 6:
            return "TCP协议";
        case 17:
            return "UDP协议";
        default:
            return "其他";
    }
}
    //在控制台展示信息
    public static void showInConsole(TCPPacket tcpPacket) {
        System.out.println("Source Port: " + tcpPacket.src_port);
        System.out.println("Destination Port: " + tcpPacket.dst_port);
        System.out.println("Sequence Number: " + tcpPacket.sequence);
        System.out.println("Acknowledgment Number: " + tcpPacket.ack_num);
        System.out.println("Data Offset: " + tcpPacket.header.length);
        if(tcpPacket.urg){
            System.out.println("URG Flag: 该报文有紧急数据" );
        }
        if(tcpPacket.ack){
            System.out.println("ACK Flag: 确认字段有效" );
        }else{
            System.out.println("ACK Flag: 确认字段无效" );
        }
        if(tcpPacket.psh){
            System.out.println("PSH Flag: 立即推送" );
        }
        if (tcpPacket.rst){
            System.out.println("RST Flag: 重置连接" );
        }
        if (tcpPacket.syn){
            System.out.println("SYN Flag: 同步连接" );
        }
        if (tcpPacket.fin){
            System.out.println("FIN Flag: 结束连接" );
        }
        System.out.println("Window Size: " + tcpPacket.window);
        System.out.println("Urgent Pointer: " + tcpPacket.urgent_pointer);
        System.out.println("Options: " + tcpPacket.option);
        System.out.println("Protocol: " + tcpPacket.protocol);
        System.out.println("Data: " + new String(tcpPacket.data));
        System.out.println("------------");
    }
    public static int calculateDataOffset(TCPPacket tcpPacket) {
        // TCP头长度存储在第12字节的前4位
        // TCP 标头长度字段以 4 字节为单位，因此乘以 4 即可得到字节
        return (tcpPacket.header[12] & 0xF0) >> 4;
    }
    // 计算 TCP 校验和的函数
    public static long calculateChecksum(TCPPacket tcpPacket) {
        // 初始化校验和
        CRC32 crc = new CRC32();

        // 准备计算校验和的数据：TCP伪头+TCP头+TCP数据
        byte[] pseudoHeader = preparePseudoHeader(tcpPacket);
        byte[] tcpHeader = tcpPacket.header;
        byte[] tcpData = tcpPacket.data;

        // 将伪标头、TCP 标头和 TCP 数据合并到单个字节数组中
        byte[] combinedData = new byte[pseudoHeader.length + tcpHeader.length + tcpData.length];
        System.arraycopy(pseudoHeader, 0, combinedData, 0, pseudoHeader.length);
        System.arraycopy(tcpHeader, 0, combinedData, pseudoHeader.length, tcpHeader.length);
        System.arraycopy(tcpData, 0, combinedData, pseudoHeader.length + tcpHeader.length, tcpData.length);

        // 使用组合数据更新 CRC32
        crc.update(combinedData);

        // 获取计算出的校验和
        return crc.getValue();
    }

    // 准备 TCP 伪标头的函数
    private static byte[] preparePseudoHeader(TCPPacket tcpPacket) {
        // 伪标头包括：
        // 源IP地址（4字节）
        // 目标IP地址（4字节）
        // 保留（1 字节）
        // 协议（1字节）
        // TCP 长度（2 字节）
        byte[] pseudoHeader = new byte[12];

        // 获取源IP地址和目的IP地址
        byte[] srcAddress = tcpPacket.src_ip.getAddress();
        byte[] dstAddress = tcpPacket.dst_ip.getAddress();

        // 将源和目标 IP 地址复制到伪标头中
        System.arraycopy(srcAddress, 0, pseudoHeader, 0, 4);
        System.arraycopy(dstAddress, 0, pseudoHeader, 4, 4);

        // 将保留字段设置为 0
        pseudoHeader[8] = 0;

        // 将协议字段设置为 6 (TCP)
        pseudoHeader[9] = 6;

        // 获取TCP长度（报头长度+数据长度）
        int tcpLength = tcpPacket.header.length + tcpPacket.data.length;

        // 设置伪标头中的 TCP 长度
        pseudoHeader[10] = (byte) ((tcpLength >> 8) & 0xFF);
        pseudoHeader[11] = (byte) (tcpLength & 0xFF);

        return pseudoHeader;
    }
}
