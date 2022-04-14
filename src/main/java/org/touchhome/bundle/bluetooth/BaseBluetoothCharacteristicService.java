package org.touchhome.bundle.bluetooth;

import com.pivovarit.function.ThrowingRunnable;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.SystemUtils;
import org.ble.BleApplicationListener;
import org.ble.BluetoothApplication;
import org.dbus.InterfacesAddedSignal.InterfacesAdded;
import org.dbus.InterfacesRomovedSignal.InterfacesRemoved;
import org.freedesktop.dbus.Variant;
import org.touchhome.bundle.api.hardware.network.Network;
import org.touchhome.bundle.api.hardware.network.NetworkHardwareRepository;
import org.touchhome.bundle.api.hardware.other.MachineHardwareRepository;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.stream.Collectors;

@Log4j2
@RequiredArgsConstructor
public abstract class BaseBluetoothCharacteristicService {

    public static final int MIN_WRITE_TIMEOUT = 10000; // 10 sec
    private static final String PREFIX = "13333333-3333-3333-3333-3333333330";
    private static final String SERVICE_UUID = PREFIX + "00";
    private static final String CPU_LOAD_UUID = PREFIX + "01";
    private static final String CPU_TEMP_UUID = PREFIX + "02";
    private static final String DEVICE_MODEL_UUID = PREFIX + "03";
    private static final String MEMORY_UUID = PREFIX + "04";
    private static final String UPTIME_UUID = PREFIX + "05";
    private static final String WIFI_NAME_UUID = PREFIX + "06";
    private static final String IP_ADDRESS_UUID = PREFIX + "07";
    private static final String PWD_SET_UUID = PREFIX + "08";
    private static final String KEYSTORE_SET_UUID = PREFIX + "09";
    private static final String WIFI_LIST_UUID = PREFIX + "10";
    private static final String SD_MEMORY_UUID = PREFIX + "11";
    private static final String WRITE_BAN_UUID = PREFIX + "12";
    private static final String SERVER_CONNECTED_UUID = PREFIX + "13";
    private static final String FEATURES_UUID = PREFIX + "14";
    private static final int TIME_REFRESH_PASSWORD = 5 * 60000; // 5 minute for session
    private static long timeSinceLastCheckPassword = -1;
    private final MachineHardwareRepository machineHardwareRepository;
    private final NetworkHardwareRepository networkHardwareRepository;
    private final Map<String, Long> wifiWriteProtect = new ConcurrentHashMap<>();
    private BluetoothApplication bluetoothApplication;
    private String loginUser;

    public String getDeviceCharacteristic(String uuid) {
        switch (uuid) {
            case CPU_LOAD_UUID:
                return readIfLinux(machineHardwareRepository::getCpuLoad);
            case CPU_TEMP_UUID:
                return readIfLinux(this::getCpuTemp);
            case MEMORY_UUID:
                return readIfLinux(machineHardwareRepository::getMemory);
            case SD_MEMORY_UUID:
                return readIfLinux(() -> machineHardwareRepository.getSDCardMemory().toString());
            case UPTIME_UUID:
                return readIfLinux(machineHardwareRepository::getUptime);
            case IP_ADDRESS_UUID:
                return getUserIPAddress();
            case WRITE_BAN_UUID:
                return gatherWriteBan();
            case DEVICE_MODEL_UUID:
                return readIfLinux(machineHardwareRepository::getDeviceModel);
            case SERVER_CONNECTED_UUID:
                return readSafeValue(this::readServerConnected);
            case WIFI_LIST_UUID:
                return readIfLinux(this::readWifiList);
            case WIFI_NAME_UUID:
                return readIfLinux(this::getWifiName);
            case KEYSTORE_SET_UUID:
                return readSafeValue(this::getKeystore);
            case PWD_SET_UUID:
                return readPwdSet();
            case FEATURES_UUID:
                return readSafeValue(this::getFeatures);
        }
        return null;
    }

    private String gatherWriteBan() {
        List<String> status = new ArrayList<>();
        for (Map.Entry<String, Long> entry : wifiWriteProtect.entrySet()) {
            if (System.currentTimeMillis() - entry.getValue() < MIN_WRITE_TIMEOUT) {
                status.add(entry.getKey() + "%&%" + ((MIN_WRITE_TIMEOUT - (System.currentTimeMillis() - entry.getValue())) / 1000));
            }
        }
        return String.join("%#%", status);
    }

    public void setDeviceCharacteristic(String uuid, byte[] value) {
        if (value != null && (!wifiWriteProtect.containsKey(uuid) || System.currentTimeMillis() - wifiWriteProtect.get(uuid) > MIN_WRITE_TIMEOUT)) {
            wifiWriteProtect.put(uuid, System.currentTimeMillis());
            switch (uuid) {
                case DEVICE_MODEL_UUID:
                    rebootDevice(null);
                    return;
                case WIFI_NAME_UUID:
                    writeWifiSSID(value);
                    return;
                case PWD_SET_UUID:
                    writePwd(value);
                    return;
                case KEYSTORE_SET_UUID:
                    writeKeystore(value);
            }
        }
    }

    private static boolean isLinuxEnvironment() {
        return SystemUtils.IS_OS_LINUX && !"true".equals(System.getProperty("development"));
    }

    public void init() {
        log.info("Starting bluetooth...");

        if (!isLinuxEnvironment()) {
            log.warn("Bluetooth skipped for non linux env. Require unix sockets");
            updateBluetoothStatus("OFFLINE");
            return;
        }

        bluetoothApplication = new BluetoothApplication("touchHome", SERVICE_UUID, new BleApplicationListener() {
            @Override
            public void deviceConnected(Variant<String> address, InterfacesAdded signal) {
                log.info("Device connected. Address: <{}>. Path: <{}>", address.getValue(), signal.getObjectPath());
                timeSinceLastCheckPassword = -1;
            }

            @Override
            public void deviceDisconnected(InterfacesRemoved signal) {
                log.info("Device disconnected. Path: <{}>", signal.getObjectPath());
                timeSinceLastCheckPassword = -1;
            }
        });

        bluetoothApplication.newReadCharacteristic("cpu_load", CPU_LOAD_UUID, () -> readIfLinux(machineHardwareRepository::getCpuLoad).getBytes());
        bluetoothApplication.newReadCharacteristic("cpu_temp", CPU_TEMP_UUID, () -> readIfLinux(this::getCpuTemp).getBytes());
        bluetoothApplication.newReadCharacteristic("memory", MEMORY_UUID, () -> readIfLinux(machineHardwareRepository::getMemory).getBytes());
        bluetoothApplication.newReadCharacteristic("sd_memory", SD_MEMORY_UUID, () -> readIfLinux(() -> machineHardwareRepository.getSDCardMemory().toString()).getBytes());
        bluetoothApplication.newReadCharacteristic("uptime", UPTIME_UUID, () -> readIfLinux(machineHardwareRepository::getUptime).getBytes());
        bluetoothApplication.newReadCharacteristic("ip", IP_ADDRESS_UUID, () -> getUserIPAddress().getBytes());
        bluetoothApplication.newReadCharacteristic("write_ban", WRITE_BAN_UUID, () -> bluetoothApplication.gatherWriteBan().getBytes());
        bluetoothApplication.newReadWriteCharacteristic("device_model", DEVICE_MODEL_UUID, this::rebootDevice, () -> readIfLinux(machineHardwareRepository::getDeviceModel).getBytes());
        bluetoothApplication.newReadCharacteristic("server_connected", SERVER_CONNECTED_UUID, () -> readSafeValue(this::readServerConnected).getBytes());
        bluetoothApplication.newReadCharacteristic("wifi_list", WIFI_LIST_UUID, () -> readIfLinux(this::readWifiList).getBytes());
        bluetoothApplication.newReadWriteCharacteristic("wifi_name", WIFI_NAME_UUID, this::writeWifiSSID, () -> readIfLinux(this::getWifiName).getBytes());
        bluetoothApplication.newReadWriteCharacteristic("pwd", PWD_SET_UUID, this::writePwd, () -> readPwdSet().getBytes());
        bluetoothApplication.newReadWriteCharacteristic("features", FEATURES_UUID, this::updateFeature, () -> readSafeValue(this::getFeatures).getBytes());

        bluetoothApplication.newReadWriteCharacteristic("keystore", KEYSTORE_SET_UUID, this::writeKeystore,
                () -> readSafeValue(this::getKeystore).getBytes());

        // start ble
        try {
            bluetoothApplication.start();
            log.info("Bluetooth successfully started");
            setFeatureState(true);
            updateBluetoothStatus("ONLINE");
        } catch (Throwable ex) {
            updateBluetoothStatus("ERROR#~#" + ex.getMessage());
            setFeatureState(false);
            log.error("Unable to start bluetooth service", ex);
        }
    }

    private String readTimeToReleaseSession() {
        return Long.toString((TIME_REFRESH_PASSWORD - (System.currentTimeMillis() - timeSinceLastCheckPassword)) / 1000);
    }

    public void writeKeystore(byte[] bytes) {

    }

    private String getUserIPAddress() {
        return readIfLinux(networkHardwareRepository::getIPAddress) + "%&%" + this.loginUser;
    }

    /**
     * We may set password only once. If user wants update password, he need pass old password hash
     */
    private void writePwd(byte[] bytes) {
        String[] split = new String(bytes).split("%&%");
        this.loginUser = split[0];
        String pwd = split[1];
        String prevPwd = split.length > 2 ? split[2] : "";
        writePwd(loginUser, pwd, prevPwd);
    }

    public abstract void writePwd(String loginUser, String pwd, String prevPwd);

    public void updateFeature(byte[] bytes) {

    }

    private void writeWifiSSID(byte[] bytes) {
        writeSafeValue(() -> {
            String[] split = new String(bytes).split("%&%");
            if (split.length == 3 && split[1].length() >= 8) {
                log.info("Writing wifi credentials");
                networkHardwareRepository.setWifiCredentials(split[0], split[1], split[2]);
                networkHardwareRepository.restartNetworkInterface();
            }
        });
    }

    private void rebootDevice(byte[] ignore) {
        writeSafeValue(machineHardwareRepository::reboot);
    }

    public abstract String readPwdSet();

    private String readWifiList() {
        return networkHardwareRepository.scan(networkHardwareRepository.getActiveNetworkInterface()).stream()
                .filter(distinctByKey(Network::getSsid))
                .map(n -> n.getSsid() + "%&%" + n.getStrength()).collect(Collectors.joining("%#%"));
    }

    private <T> Predicate<T> distinctByKey(Function<? super T, ?> keyExtractor) {
        Set<Object> seen = ConcurrentHashMap.newKeySet();
        return t -> seen.add(keyExtractor.apply(t));
    }

    public abstract String readServerConnected();

    @SneakyThrows
    protected void writeSafeValue(ThrowingRunnable<Exception> runnable) {
        if (hasAccess()) {
            runnable.run();
        }
    }

    private String readSafeValue(Supplier<String> supplier) {
        if (hasAccess()) {
            return supplier.get();
        }
        return "";
    }

    private String readIfLinux(Supplier<String> supplier) {
        if (hasAccess() && isLinuxEnvironment()) {
            return supplier.get();
        }
        return "";
    }

    private boolean hasAccess() {
        return System.currentTimeMillis() - timeSinceLastCheckPassword < TIME_REFRESH_PASSWORD || hasExtraAccess();
    }

    public abstract boolean hasExtraAccess();

    public abstract String getFeatures();

    private String getWifiName() {
        return machineHardwareRepository.getWifiName();
    }

    @SneakyThrows
    private String getCpuTemp() {
        return machineHardwareRepository.getCpuTemperature();
    }

    public abstract String getKeystore();

    public abstract void updateBluetoothStatus(String status);

    public abstract void setFeatureState(boolean status);
}
