//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package weblogic.jms.common;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectOutput;
import javax.jms.JMSException;
import javax.jms.StreamMessage;

import weblogic.jms.JMSClientExceptionLogger;

public final class StreamMessageImpl extends MessageImpl implements StreamMessage, Externalizable {
    static final long serialVersionUID = 7748687583664395357L;
    private transient byte[] buffer;
    private transient int length;
    private transient PayloadStream payload;
    private transient boolean copyOnWrite;
    private transient BufferOutputStream bos;


    public StreamMessageImpl() {
    }


    public byte getType() {
        return 5;
    }

    public void nullBody() {
        this.length = 0;
        this.buffer = null;
        this.copyOnWrite = false;
    }


    private String streamWriteError() {
        return JMSClientExceptionLogger.logStreamWriteErrorLoggable().getMessage();
    }

    private String streamWriteError(int var1) {
        return JMSClientExceptionLogger.logWriteErrorLoggable(var1).getMessage();
    }

    private void writeType(byte var1) throws JMSException {
        this.checkWritable();

        try {
            this.bos.writeByte(var1);
        } catch (IOException var3) {
            throw new weblogic.jms.common.JMSException(JMSClientExceptionLogger.logStreamWriteErrorLoggable().getMessage(), var3);
        }
    }


    @Override
    public boolean readBoolean() throws JMSException {
        return false;
    }

    @Override
    public byte readByte() throws JMSException {
        return 0;
    }

    @Override
    public short readShort() throws JMSException {
        return 0;
    }

    @Override
    public char readChar() throws JMSException {
        return 0;
    }

    @Override
    public int readInt() throws JMSException {
        return 0;
    }

    @Override
    public long readLong() throws JMSException {
        return 0;
    }

    @Override
    public float readFloat() throws JMSException {
        return 0;
    }

    @Override
    public double readDouble() throws JMSException {
        return 0;
    }

    @Override
    public String readString() throws JMSException {
        return null;
    }

    @Override
    public int readBytes(byte[] bytes) throws JMSException {
        return 0;
    }

    @Override
    public Object readObject() throws JMSException {
        return null;
    }

    public void writeBoolean(boolean var1) throws JMSException {
        this.writeType((byte) 1);

        try {
            this.bos.writeBoolean(var1);
        } catch (IOException var3) {
            throw new weblogic.jms.common.JMSException(this.streamWriteError(10), var3);
        }
    }

    public void writeByte(byte var1) throws JMSException {
        this.writeType((byte) 2);

        try {
            this.bos.writeByte(var1);
        } catch (IOException var3) {
            throw new weblogic.jms.common.JMSException(this.streamWriteError(20), var3);
        }
    }

    public void writeShort(short var1) throws JMSException {
        this.writeType((byte) 8);

        try {
            this.bos.writeShort(var1);
        } catch (IOException var3) {
            throw new weblogic.jms.common.JMSException(this.streamWriteError(30), var3);
        }
    }

    public void writeChar(char var1) throws JMSException {
        this.writeType((byte) 3);

        try {
            this.bos.writeChar(var1);
        } catch (IOException var3) {
            throw new weblogic.jms.common.JMSException(this.streamWriteError(40), var3);
        }
    }

    public void writeInt(int var1) throws JMSException {
        this.writeType((byte) 6);

        try {
            this.bos.writeInt(var1);
        } catch (IOException var3) {
            throw new weblogic.jms.common.JMSException(this.streamWriteError(50), var3);
        }
    }

    public void writeLong(long var1) throws JMSException {
        this.writeType((byte) 7);

        try {
            this.bos.writeLong(var1);
        } catch (IOException var4) {
            throw new weblogic.jms.common.JMSException(this.streamWriteError(60), var4);
        }
    }

    public void writeFloat(float var1) throws JMSException {
        this.writeType((byte) 5);

        try {
            this.bos.writeFloat(var1);
        } catch (IOException var3) {
            throw new weblogic.jms.common.JMSException(this.streamWriteError(70), var3);
        }
    }

    public void writeDouble(double var1) throws JMSException {
        this.writeType((byte) 4);

        try {
            this.bos.writeDouble(var1);
        } catch (IOException var4) {
            throw new weblogic.jms.common.JMSException(this.streamWriteError(80), var4);
        }
    }

    public void writeString(String var1) throws JMSException {
        if (var1 == null) {
            this.writeType((byte) 12);
        } else {
            try {
                this.writeStringInternal(var1);
            } catch (IOException var3) {
                throw new weblogic.jms.common.JMSException(this.streamWriteError(), var3);
            }
        }

    }

    public void writeBytes(byte[] var1) throws JMSException {
        this.writeBytes(var1, 0, var1.length);
    }

    public void writeBytes(byte[] var1, int var2, int var3) throws JMSException {
        if (var1 == null) {
            throw new NullPointerException();
        } else {
            this.writeType((byte) 11);

            try {
                this.bos.writeInt(var3);
                this.bos.write(var1, var2, var3);
            } catch (IOException var5) {
                throw new weblogic.jms.common.JMSException(this.streamWriteError(100), var5);
            }
        }
    }

    public void writeObject(Object var1) throws JMSException {
        if (var1 instanceof Boolean) {
            this.writeBoolean((Boolean) var1);
        } else if (var1 instanceof Number) {
            if (var1 instanceof Byte) {
                this.writeByte((Byte) var1);
            } else if (var1 instanceof Double) {
                this.writeDouble((Double) var1);
            } else if (var1 instanceof Float) {
                this.writeFloat((Float) var1);
            } else if (var1 instanceof Integer) {
                this.writeInt((Integer) var1);
            } else if (var1 instanceof Long) {
                this.writeLong((Long) var1);
            } else if (var1 instanceof Short) {
                this.writeShort((Short) var1);
            }
        } else if (var1 instanceof Character) {
            this.writeChar((Character) var1);
        } else if (var1 instanceof String) {
            this.writeString((String) var1);
        } else if (var1 instanceof byte[]) {
            this.writeBytes((byte[]) ((byte[]) var1));
        } else {
            if (var1 != null) {
                throw new MessageFormatException("Invalid Type: " + var1.getClass().getName());
            }

            this.writeType((byte) 12);
        }

    }

    public MessageImpl copy() throws JMSException {
        StreamMessageImpl var1 = new StreamMessageImpl();
        super.copy(var1);
        if (this.bos != null) {
            var1.payload = this.bos.copyPayloadWithoutSharedStream();
        } else if (this.payload != null) {
            var1.payload = this.payload.copyPayloadWithoutSharedStream();
        }

        var1.copyOnWrite = this.copyOnWrite = true;
        var1.setBodyWritable(false);
        var1.setPropertiesWritable(false);
        return var1;
    }

    private void checkWritable() throws JMSException {
        super.writeMode();
        if (this.bos == null) {
            this.bos = PayloadFactoryImpl.createOutputStream();
        } else if (this.copyOnWrite) {
            this.bos.copyBuffer();
            this.copyOnWrite = false;
        }

    }


    public String toString() {
        return "StreamMessage[" + this.getJMSMessageID() + "]";
    }

    public final byte[] getDataBuffer() {
        return this.buffer;
    }

    public final int getDataSize() {
        return this.length;
    }

    public final void setDataBuffer(byte[] var1, int var2) {
        this.buffer = var1;
        this.length = var2;
    }

    public void writeExternal(ObjectOutput paramObjectOutput) throws IOException {
        super.writeExternal(paramObjectOutput);
        paramObjectOutput.writeByte(1);
        paramObjectOutput.writeInt(getDataSize());
        paramObjectOutput.write(getDataBuffer());
    }


    public long getPayloadSize() {
        if (this.isCompressed()) {
            return (long) this.getCompressedMessageBodySize();
        } else if (super.bodySize != -1L) {
            return super.bodySize;
        } else if (this.payload != null) {
            return super.bodySize = (long) this.payload.getLength();
        } else {
            return this.bos != null ? (long) this.bos.size() : (super.bodySize = 0L);
        }
    }

    @Override
    public void decompressMessageBody() throws JMSException {

    }

    private void writeStringInternal(String var1) throws IOException, JMSException {
        if (var1.length() > 20000) {
            this.writeType((byte) 10);
            this.bos.writeUTF32(var1);
        } else {
            this.writeType((byte) 9);
            this.bos.writeUTF(var1);
        }

    }
}