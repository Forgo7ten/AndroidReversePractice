package my.test;


import com.sun.mail.imap.IMAPStore;

import javax.mail.*;
import java.util.*;

/**
 * @ClassName MyMail
 * @Description //TODO
 * @Author Palmer
 * @Date 2021/11/27
 **/
public class MyMail {
    private String mUserAddr;
    private String mPassword;
    private IMAPStore mStore = null;

    public MyMail(String mUserAddr, String mPassword) {
        this.mUserAddr = mUserAddr;
        this.mPassword = mPassword;
        this.connect();
    }


    public String getmUserAddr() {
        return mUserAddr;
    }

    public void setmUserAddr(String mUserAddr) {
        this.mUserAddr = mUserAddr;
    }

    public String getmPassword() {
        return mPassword;
    }

    public void setmPassword(String mPassword) {
        this.mPassword = mPassword;
    }

    public IMAPStore getmStore() {
        return mStore;
    }

    public void setmStore(IMAPStore mStore) {
        this.mStore = mStore;
    }

    public Store connect() {
        // 准备连接服务器的会话信息
        Properties props = new Properties();
        props.setProperty("mail.store.protocol", "imap");
        props.setProperty("mail.imap.host", "imap.163.com");
        props.setProperty("mail.imap.port", "143");

        //带上IMAP ID信息，由key和value组成，例如name，version，vendor，support-email等。
        Map<String, String> iam = new HashMap<String, String>() {
            {
                put("name", mUserAddr.split("@")[0]);
                put("version", "1.0.0");
                put("vendor", "my_java_client");
                put("support-email", mUserAddr);
            }
        };
        // 创建Session实例对象
        Session session = Session.getInstance(props);

        try {
            // 创建IMAP协议的Store对象
            mStore = (IMAPStore) session.getStore("imap");
            // 连接邮件服务器
            mStore.connect(mUserAddr, mPassword);
            mStore.id(iam);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
        return mStore;
    }

    public List<Message> getMailsInFolder(String folderName) {
        List<Message> messageList = new ArrayList<>();
        try {
            Folder folder = this.mStore.getFolder(folderName);
            // 以只读模式打开邮件
            folder.open(Folder.READ_ONLY);
            Message[] messages = folder.getMessages();
            messageList.addAll(Arrays.asList(messages));
        } catch (MessagingException e) {
            e.printStackTrace();
        }
        return messageList;
    }

}
