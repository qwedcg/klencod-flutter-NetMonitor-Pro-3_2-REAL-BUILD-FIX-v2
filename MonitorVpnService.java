package com.netmonitor.pro;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Real Android VPN monitor.
 *
 * The VPN TUN is forwarded by hev-socks5-tunnel.  The Java SOCKS5 relay is
 * deliberately local and uses VpnService.protect() for every real Internet
 * socket so that the relay itself does not loop back into the VPN.
 * Destination IP/port information is collected at the SOCKS5 boundary.
 */
public class MonitorVpnService extends VpnService {
    public static final String ACTION_START = "START";
    private static final String PREFS = "netmonitor";
    private static final int SOCKS_PORT = 1080;
    private static final int MTU = 1500;

    private ParcelFileDescriptor vpn;
    private ServerSocket socksServer;
    private Thread socksThread;
    private static volatile boolean running;

    private static final Object LOCK = new Object();
    private static final LinkedHashSet<String> IPS = new LinkedHashSet<>();
    private static final LinkedHashSet<Integer> PORTS = new LinkedHashSet<>();
    private static final List<Record> RECORDS = new ArrayList<>();
    private static final Set<String> FLOW_KEYS = ConcurrentHashMap.newKeySet();
    private static long packets;
    private static String detectedGame = "";
    private static String lastError = "";
    private Thread nativeStatsThread;

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        createChannel();
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(10, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(10, notification());
        }
        if (ACTION_START.equals(intent != null ? intent.getAction() : null)) startCapture();
        return START_STICKY;
    }

    private synchronized void startCapture() {
        if (running) return;
        SharedPreferences pref = getSharedPreferences(PREFS, MODE_PRIVATE);
        try {
            Builder b = new Builder()
                    .setSession("NetMonitor Pro")
                    .setBlocking(true)
                    .setMtu(MTU)
                    .addAddress("198.18.0.1", 15)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer("1.1.1.1");

            String selected = pref.getString("apps", "");
            if (!selected.isEmpty()) {
                for (String pkg : selected.split("\\|")) {
                    if (!pkg.isEmpty()) {
                        try { b.addAllowedApplication(pkg); } catch (Exception ignored) {}
                    }
                }
            } else {
                // Do not route NetMonitor's own local SOCKS relay through itself.
                try { b.addDisallowedApplication(getPackageName()); } catch (Exception ignored) {}
            }

            vpn = b.establish();
            if (vpn == null) throw new IOException("VPN establish returned null");

            startSocksServer();
            writeTunnelConfig();

            boolean started = NativeTunnelService.TProxyStartService(
                    new File(getFilesDir(), "hev.yml").getAbsolutePath(),
                    vpn.getFd());
            if (!started) throw new IOException("hev-socks5-tunnel returned false");
            running = true;
            lastError = "";
            startNativeStatsPoller();
        } catch (Throwable e) {
            lastError = e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage());
            stopInternals();
        }
    }

    private void startSocksServer() throws IOException {
        socksServer = new ServerSocket();
        socksServer.setReuseAddress(true);
        socksServer.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), SOCKS_PORT));
        socksThread = new Thread(() -> {
            while (running && !Thread.currentThread().isInterrupted()) {
                try {
                    Socket s = socksServer.accept();
                    Thread t = new Thread(() -> handleSocksClient(s), "socks-client");
                    t.start();
                } catch (IOException e) {
                    if (socksServer == null || socksServer.isClosed()) break;
                }
            }
        }, "NetMonitor-SOCKS");
        // The server is needed before native tunnel starts. It is safe to accept
        // connections even while the service flag is being switched on.
        socksThread.setDaemon(true);
        running = true;
        socksThread.start();
    }

    private void writeTunnelConfig() throws IOException {
        String config =
                "tunnel:\n" +
                "  name: tun0\n" +
                "  mtu: 1500\n" +
                "  multi-queue: false\n" +
                "  ipv4: 198.18.0.1\n" +
                "  icmp: reply\n" +
                "socks5:\n" +
                "  address: 127.0.0.1\n" +
                "  port: 1080\n" +
                "  udp: udp\n" +
                "misc:\n" +
                "  log-level: warn\n";
        try (FileOutputStream out = new FileOutputStream(new File(getFilesDir(), "hev.yml"))) {
            out.write(config.getBytes(StandardCharsets.UTF_8));
        }
    }

    private void handleSocksClient(Socket client) {
        try (Socket c = client) {
            c.setTcpNoDelay(true);
            InputStream in = c.getInputStream();
            OutputStream out = c.getOutputStream();
            if (readU8(in) != 5) return;
            int methods = readU8(in);
            if (methods < 0) return;
            byte[] offered = readFully(in, methods);
            boolean noAuth = false;
            for (byte m : offered) if ((m & 0xff) == 0) noAuth = true;
            out.write(new byte[]{5, (byte)(noAuth ? 0 : 0xff)}); out.flush();
            if (!noAuth) return;

            if (readU8(in) != 5) return;
            int cmd = readU8(in);
            readU8(in); readU8(in);
            Endpoint ep = readEndpoint(in);
            if (ep == null) return;

            if (cmd == 1) {
                recordFlow("TCP", ep.host, ep.port);
                relayTcp(c, out, ep);
            } else if (cmd == 3) {
                handleUdpAssociate(c, out);
            } else {
                sendReply(out, 7, 0, 0);
            }
        } catch (Exception ignored) {
        }
    }

    private void relayTcp(Socket client, OutputStream clientOut, Endpoint ep) {
        try (Socket remote = new Socket()) {
            if (!protect(remote)) throw new IOException("protect(remote) failed");
            remote.connect(new InetSocketAddress(ep.host, ep.port), 10000);
            remote.setTcpNoDelay(true);
            InetSocketAddress local = (InetSocketAddress) remote.getLocalSocketAddress();
            sendReply(clientOut, 0, local.getAddress(), local.getPort());

            Thread a = new Thread(() -> pipe(client, remote), "tcp-up");
            Thread b = new Thread(() -> pipe(remote, client), "tcp-down");
            a.start(); b.start();
            a.join();
            try { remote.shutdownOutput(); } catch (Exception ignored) {}
            b.join();
        } catch (Exception e) {
            try { sendReply(clientOut, 1, 0, 0); } catch (Exception ignored) {}
        }
    }

    private void pipe(Socket from, Socket to) {
        try {
            byte[] buf = new byte[16384];
            int n;
            InputStream in = from.getInputStream();
            OutputStream out = to.getOutputStream();
            while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
            out.flush();
        } catch (IOException ignored) {}
    }

    private void handleUdpAssociate(Socket control, OutputStream controlOut) {
        DatagramSocket relay = null;
        try {
            relay = new DatagramSocket(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            if (!protect(relay)) throw new IOException("protect(udp) failed");
            int port = relay.getLocalPort();
            sendReply(controlOut, 0, InetAddress.getLoopbackAddress(), port);
            final DatagramSocket ds = relay;
            final byte[][] clientHolder = new byte[1][];
            final int[] clientPort = new int[]{-1};
            final InetAddress[] clientAddr = new InetAddress[1];
            byte[] buf = new byte[65535];

            while (!control.isClosed()) {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                ds.receive(p);
                if (clientAddr[0] == null) {
                    clientAddr[0] = p.getAddress(); clientPort[0] = p.getPort();
                }
                if (p.getAddress().equals(clientAddr[0]) && p.getPort() == clientPort[0]) {
                    UdpMessage m = parseUdpRequest(p.getData(), p.getOffset(), p.getLength());
                    if (m == null) continue;
                    recordFlow("UDP", m.host, m.port);
                    DatagramPacket q = new DatagramPacket(m.data, m.data.length,
                            InetAddress.getByName(m.host), m.port);
                    ds.send(q);
                } else if (clientAddr[0] != null) {
                    byte[] wrapped = wrapUdpReply(p.getAddress(), p.getPort(), p.getData(), p.getOffset(), p.getLength());
                    DatagramPacket q = new DatagramPacket(wrapped, wrapped.length, clientAddr[0], clientPort[0]);
                    ds.send(q);
                }
            }
        } catch (Exception ignored) {
        } finally {
            if (relay != null) relay.close();
        }
    }

    private static class UdpMessage {
        String host; int port; byte[] data;
    }

    private UdpMessage parseUdpRequest(byte[] b, int off, int len) throws Exception {
        if (len < 10) return null;
        int i = off;
        if (b[i] != 0 || b[i+1] != 0 || b[i+2] != 0) return null;
        i += 3;
        int atyp = b[i++] & 255;
        String host;
        if (atyp == 1) {
            if (i + 4 > off + len) return null;
            host = (b[i]&255)+"."+(b[i+1]&255)+"."+(b[i+2]&255)+"."+(b[i+3]&255); i += 4;
        } else if (atyp == 3) {
            int l = b[i++] & 255; if (i + l > off + len) return null;
            host = new String(b, i, l, StandardCharsets.UTF_8); i += l;
        } else if (atyp == 4) {
            if (i + 16 > off + len) return null;
            byte[] a = new byte[16]; System.arraycopy(b, i, a, 0, 16); i += 16;
            host = InetAddress.getByAddress(a).getHostAddress();
        } else return null;
        if (i + 2 > off + len) return null;
        int port = ((b[i]&255)<<8) | (b[i+1]&255); i += 2;
        UdpMessage m = new UdpMessage(); m.host=host; m.port=port;
        m.data = new byte[off + len - i]; System.arraycopy(b, i, m.data, 0, m.data.length);
        return m;
    }

    private byte[] wrapUdpReply(InetAddress host, int port, byte[] data, int off, int len) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(len + 32);
        out.write(0); out.write(0); out.write(0);
        if (host instanceof Inet4Address) {
            out.write(1); out.write(host.getAddress());
        } else {
            out.write(4); out.write(host.getAddress());
        }
        out.write((port >>> 8) & 255); out.write(port & 255);
        out.write(data, off, len);
        return out.toByteArray();
    }

    private Endpoint readEndpoint(InputStream in) throws Exception {
        int atyp = readU8(in);
        if (atyp < 0) return null;
        String host;
        if (atyp == 1) {
            byte[] a = readFully(in, 4); host = (a[0]&255)+"."+(a[1]&255)+"."+(a[2]&255)+"."+(a[3]&255);
        } else if (atyp == 3) {
            int l = readU8(in); if (l < 0) return null;
            host = new String(readFully(in, l), StandardCharsets.UTF_8);
        } else if (atyp == 4) {
            host = InetAddress.getByAddress(readFully(in, 16)).getHostAddress();
        } else return null;
        int hi = readU8(in), lo = readU8(in); if (lo < 0) return null;
        return new Endpoint(host, (hi << 8) | lo);
    }

    private static class Endpoint { final String host; final int port; Endpoint(String h,int p){host=h;port=p;} }

    private static int readU8(InputStream in) throws IOException { return in.read(); }
    private static byte[] readFully(InputStream in, int n) throws IOException {
        byte[] b = new byte[n]; int p=0;
        while (p<n) { int r=in.read(b,p,n-p); if(r<0) throw new IOException("eof"); p+=r; }
        return b;
    }

    private void sendReply(OutputStream out, int code, InetAddress addr, int port) throws IOException {
        byte[] a = addr == null ? new byte[]{0,0,0,0} : addr.getAddress();
        if (a.length != 4) a = new byte[]{0,0,0,0};
        out.write(new byte[]{5,(byte)code,0,1,a[0],a[1],a[2],a[3],(byte)(port>>>8),(byte)port});
        out.flush();
    }
    private void sendReply(OutputStream out, int code, int unused1, int unused2) throws IOException { sendReply(out,code,null,0); }

    private void recordFlow(String protocol, String host, int port) {
        SharedPreferences pref = getSharedPreferences(PREFS, MODE_PRIVATE);
        int min = pref.getInt("minPort", 1), max = pref.getInt("maxPort", 65535);
        if (port < min || port > max) return;
        String game = detectGame(port);
        if (pref.getBoolean("gameOnly", false) && game.isEmpty()) return;

        List<String> destinations = new ArrayList<>();
        if (isIpLiteral(host)) {
            destinations.add(host);
        } else {
            try {
                InetAddress[] resolved = InetAddress.getAllByName(host);
                for (InetAddress a : resolved) destinations.add(a.getHostAddress());
            } catch (Exception ignored) {
                destinations.add(host);
            }
        }

        synchronized (LOCK) {
            if (!game.isEmpty()) detectedGame = game;
            for (String ip : destinations) {
                String key = protocol + "|" + ip + "|" + port;
                boolean fresh = FLOW_KEYS.add(key);
                IPS.add(ip);
                PORTS.add(port);
                if (!fresh) continue;
                if (RECORDS.size() >= 5000) RECORDS.remove(0);
                RECORDS.add(new Record(now(), protocol, ip, port, selectedAppLabel()));
            }
        }
    }

    private static boolean isIpLiteral(String host) {
        return host != null && (host.matches("\\d{1,3}(\\.\\d{1,3}){3}") || host.contains(":"));
    }

    private void startNativeStatsPoller() {
        nativeStatsThread = new Thread(() -> {
            while (running && !Thread.currentThread().isInterrupted()) {
                try {
                    long[] st = NativeTunnelService.TProxyGetStats();
                    if (st != null && st.length >= 4) {
                        synchronized (LOCK) { packets = Math.max(packets, st[0] + st[2]); }
                    }
                    Thread.sleep(1000);
                } catch (Throwable ignored) { break; }
            }
        }, "NetMonitor-NativeStats");
        nativeStatsThread.setDaemon(true);
        nativeStatsThread.start();
    }

    private String selectedAppLabel() {
        SharedPreferences p = getSharedPreferences(PREFS, MODE_PRIVATE);
        String raw = p.getString("apps", "");
        if (raw.isEmpty()) return "كل التطبيقات";
        String[] pkgs = raw.split("\\|");
        if (pkgs.length == 1) {
            try {
                android.content.pm.ApplicationInfo ai = getPackageManager().getApplicationInfo(pkgs[0], 0);
                return String.valueOf(getPackageManager().getApplicationLabel(ai));
            } catch (Exception ignored) {}
        }
        return pkgs.length + " تطبيقات محددة";
    }

    private String detectGame(int port) {
        String raw = getSharedPreferences(PREFS, MODE_PRIVATE).getString("apps", "");
        for (String pkg : raw.isEmpty() ? new String[0] : raw.split("\\|")) {
            if (pkg.equals("com.tencent.ig") && port >= 8000 && port <= 21000) return "PUBG Mobile";
            if (pkg.equals("com.dts.freefireth") && port >= 7000 && port <= 20000) return "Free Fire";
            if (pkg.equals("com.activision.callofduty.shooter") && port >= 8000 && port <= 22000) return "Call of Duty";
            if (pkg.equals("com.mobile.legends") && port >= 6000 && port <= 18000) return "Mobile Legends";
            if (pkg.equals("com.miHoYo.GenshinImpact") && port == 443) return "Genshin Impact";
            if (pkg.equals("com.supercell.clashofclans") && port == 9339) return "Clash of Clans";
            if (pkg.equals("com.supercell.brawlstars") && port == 9339) return "Brawl Stars";
        }
        return "";
    }

    private static String now() { return new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date()); }

    public static Stats getStats() {
        synchronized (LOCK) {
            StringBuilder sb = new StringBuilder();
            for (Record r : RECORDS) sb.append(r.protocol).append(" | ").append(r.ip).append(" | ").append(r.port)
                    .append(" | ").append(r.time).append(" | ").append(r.owner).append('\n');
            return new Stats(IPS.size(), PORTS.size(), packets, detectedGame, sb.toString(), lastError);
        }
    }
    public static void clearRecords() { synchronized (LOCK) { IPS.clear(); PORTS.clear(); RECORDS.clear(); FLOW_KEYS.clear(); packets=0; detectedGame=""; } }
    public static boolean isRunning() { return running; }

    public static String exportCsv() {
        synchronized (LOCK) {
            StringBuilder s=new StringBuilder("Time,Protocol,IP,Port,App\n");
            for(Record r:RECORDS)s.append(csv(r.time)).append(',').append(csv(r.protocol)).append(',').append(csv(r.ip)).append(',').append(r.port).append(',').append(csv(r.owner)).append('\n');
            return s.toString();
        }
    }
    public static String exportJson() {
        synchronized (LOCK) {
            StringBuilder s=new StringBuilder("[\n");
            for(int i=0;i<RECORDS.size();i++){Record r=RECORDS.get(i);s.append("  {\"timestamp\":\"").append(json(r.time)).append("\",\"protocol\":\"").append(json(r.protocol)).append("\",\"ip\":\"").append(json(r.ip)).append("\",\"port\":").append(r.port).append(",\"app\":\"").append(json(r.owner)).append("\"}");if(i+1<RECORDS.size())s.append(',');s.append('\n');}return s.append(']').toString();
        }
    }
    private static String csv(String s){return "\""+s.replace("\"","\"\"")+"\"";}
    private static String json(String s){return s.replace("\\","\\\\").replace("\"","\\\"");}

    private void createChannel(){NotificationChannel c=new NotificationChannel("netmonitor","NetMonitor Pro",NotificationManager.IMPORTANCE_LOW);getSystemService(NotificationManager.class).createNotificationChannel(c);}
    private Notification notification(){return new Notification.Builder(this,"netmonitor").setContentTitle("NetMonitor Pro").setContentText("مراقبة اتصالات الشبكة تعمل").setSmallIcon(android.R.drawable.stat_sys_warning).build();}

    private synchronized void stopInternals(){
        running=false;
        try{NativeTunnelService.TProxyStopService();}catch(Throwable ignored){}
        if (nativeStatsThread != null) { try { nativeStatsThread.interrupt(); } catch (Exception ignored) {} nativeStatsThread = null; }
        try{if(socksServer!=null)socksServer.close();}catch(Exception ignored){}
        socksServer=null;
        try{if(vpn!=null)vpn.close();}catch(Exception ignored){}
        vpn=null;
    }
    @Override public void onDestroy(){stopInternals();super.onDestroy();}

    public static class Stats{public final int ips,ports;public final long packets;public final String game,log,error;Stats(int i,int p,long n,String g,String l,String e){ips=i;ports=p;packets=n;game=g;log=l;error=e;}}
    private static class Record{final String time,protocol,ip,owner;final int port;Record(String t,String p,String i,int po,String a){time=t;protocol=p;ip=i;port=po;owner=a;}}
}

/** JNI bridge kept in this source file so the flat GitHub build cannot omit it. */
final class NativeTunnelService {
    static {
        System.loadLibrary("hev-socks5-tunnel");
    }
    private NativeTunnelService() {}
    static native boolean TProxyStartService(String configPath, int fd);
    static native boolean TProxyStopService();
    static native boolean TProxyIsRunning();
    static native long[] TProxyGetStats();
}
