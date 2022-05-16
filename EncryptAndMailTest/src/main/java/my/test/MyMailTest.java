package my.test;


import com.sun.mail.imap.IMAPMessage;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMultipart;
import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @ClassName MyMailTest
 * @Description //TODO
 * @Author Palmer
 * @Date 2021/11/27
 **/
public class MyMailTest {
    public static final String XW_FILE = "F:\\palmer\\乱七八糟文档\\2021校赛\\邮箱邮件信息统计\\校外邮寄地址整理.csv";
    public static final String XN_FILE = "F:\\palmer\\乱七八糟文档\\2021校赛\\邮箱邮件信息统计\\校内奖品整理.csv";
    public static final String LOG_FILE = "F:\\palmer\\乱七八糟文档\\2021校赛\\邮箱邮件信息统计\\log.txt";
    public static List<Map<String, String>> xwInfos = new ArrayList<>();
    public static List<Map<String, String>> xnInfos = new ArrayList<>();
    public static StringBuffer logInfo = new StringBuffer();

    public static void parseXwMail(String content, String subject, String fromEmail) {
        content = content.replace("\r\n\r\n", "\n").replace("\r\n", "\n").replace("\r", "").replace("&nbsp;", " ");
        String[] rows = content.split("\n");
        String splitCh = "=";
        String id = "";
        String code = "";
        String to = "";
        String iphone = "";
        String address = "";
        try {
            for (String row : rows) {
                if (row.contains("获奖ID")) {
                    id = row.split(splitCh)[1].trim();
                } else if (row.contains("在线验证码")) {
                    code = row.split(splitCh)[1].trim();
                } else if (row.contains("收件人")) {
                    to = row.split(splitCh)[1].trim();
                } else if (row.contains("手机号码")) {
                    iphone = row.split(splitCh)[1].trim();
                } else if (row.contains("收货地址")) {
                    address = row.split(splitCh)[1].trim();
                }
            }
            String mid = id;
            String mcode = code;
            String mto = to;
            String miphone = iphone;
            String maddress = address;
        /*System.out.println("获奖ID = " + mid + "\n"
                + "验证码 = " + mcode + "\n"
                + "收件人 = " + mto + "\n"
                + "手机号码 = " + miphone + "\n"
                + "收货地址 = " + maddress);*/
            HashMap<String, String> xwInfo = new HashMap<String, String>() {{
                put("id", mid);
                put("code", mcode);
                put("to", mto);
                put("iphone", miphone);
                put("address", maddress);
                put("from_email", fromEmail);
            }};
            xwInfos.add(xwInfo);
        } catch (Exception e) {
            logInfo.append("        --->> " + subject + " 解析出错！<<---\n");
        }
    }

    private static void parseXnMail(String content, String subject, String fromEmail) {
        content = content.replace("\r\n\r\n", "\n").replace("\r\n", "\n").replace("\r", "").replace("&nbsp;", " ");
        String[] rows = content.split("\n");
        int len = rows.length;
        String splitCh = "=";
        String tid = "";
        String ttotal = "";
        StringBuffer tmpPrize = new StringBuffer();
        try {
            for (String row : rows) {
                if (row.contains("许愿池奖品")) {
                    String prize = row.split(splitCh)[1].split("金额")[0];
                    String money = row.split(splitCh)[1].split("金额")[1];
                    tmpPrize.append(prize.trim());
                    tmpPrize.append("(").append(money.trim()).append(") | ");
                } else if (row.contains("奖品总计")) {
                    ttotal = row.split("总计")[1].trim();
                } else if (row.contains("获奖ID")) {
                    tid = row.split(splitCh)[1].trim();
                }
            }
            tmpPrize.delete(tmpPrize.length() - 3, tmpPrize.length());
            String prize = tmpPrize.toString().trim().replace("\r", "").replace("&nbsp;", "");
            String id = tid;
            String total = ttotal;
/*        System.out.println("获奖ID = " + id + "\n"
                + "奖品列表 = " + prize + "\n"
                + "总金额 = " + total);*/

            HashMap<String, String> xnInfo = new HashMap<String, String>() {{
                put("id", id);
                put("prize", prize);
                put("total", total);
                put("from_email", fromEmail);
            }};
            xnInfos.add(xnInfo);
        } catch (Exception e) {
            logInfo.append("     --->> " + subject + " 解析出错！<<---\n");
        }
    }

    public static void checkMail(Message messageMail, boolean xwFlag) {
        IMAPMessage email = (IMAPMessage) messageMail;
        try {
            // 打印邮件标题
//            System.out.println("subject: "+email.getSubject());
            // 打印第一个发件人
//            System.out.println("From: "+email.getFrom()[0].toString());
            logInfo.append("标题：" + email.getSubject() + "  发件人：" + email.getFrom()[0].toString().split(" ")[1] + "\n");
            MimeMultipart content = (MimeMultipart) email.getContent();
            String textContent = content.getBodyPart(0).getContent().toString();
//            System.out.println(textContent);
            if (xwFlag) {
                parseXwMail(textContent, email.getSubject(), email.getFrom()[0].toString().split(" <")[1].split(">")[0]);
            } else {
                parseXnMail(textContent, email.getSubject(), email.getFrom()[0].toString().split(" <")[1].split(">")[0]);
            }
        } catch (MessagingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        String userEmail = "xxxx@163.com";
        String password = "xxxxxx";
        List<Message> emails = null;
        emails = new MyMail(userEmail, password).getMailsInFolder("校外奖品邮寄信息统计");
        logInfo.append("=====校外共" + emails.size() + "封邮件=====\n");
        for (Message email : emails) {
            checkMail(email, true);
        }
        saveXwInfo();
        emails = new MyMail(userEmail, password).getMailsInFolder("校内奖品邮寄信息统计");
        logInfo.append("=====校内共" + emails.size() + "封邮件=====\n");
        for (Message email : emails) {
            checkMail(email, false);
        }
        saveXnInfo();
        logInfo.append("Done!\n");
        printLog();
    }

    private static void printLog() {
        System.out.println(logInfo.toString());
        try {
            BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(LOG_FILE)));
            bw.write(logInfo.toString());
            bw.flush();
            bw.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void saveXnInfo() {
        try {
            BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(XN_FILE), "GB2312"));
            StringBuffer sb = new StringBuffer("获奖ID, 奖品列表, 总金额, 发信邮箱\n");
            for (Map<String, String> info : xnInfos) {
                sb.append(info.get("id") + ", ")
                        .append(info.get("prize") + ", ")
                        .append(info.get("total") + ", ")
                        .append(info.get("from_email") + "\n");
            }
            bw.write(sb.toString());
            bw.flush();
            bw.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void saveXwInfo() {
        try {
            BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(XW_FILE), "GB2312"));
            StringBuffer sb = new StringBuffer("获奖ID, 收件人, 手机号, 收件地址, 学信网验证码, 发信邮箱\n");
            for (Map<String, String> info : xwInfos) {
                sb.append(info.get("id") + ", ")
                        .append(info.get("to") + ", ")
                        .append(info.get("iphone") + ", ")
                        .append(info.get("address") + ", ")
                        .append(info.get("code") + ", ")
                        .append(info.get("from_email") + "\n");
            }
            bw.write(sb.toString());
            bw.flush();
            bw.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
