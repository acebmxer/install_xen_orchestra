# Xen Orchestra Installation for Ubuntu 24.04.3

This installation script sets up Xen Orchestra from source on a fresh Ubuntu Server 24.04.3 installation.

## Quick Start

1. Make the script executable:
```bash
chmod +x install-xen-orchestra.sh
```

2. Run the script as root:
```bash
sudo ./install-xen-orchestra.sh
```

3. Access Xen Orchestra:
   - Open a web browser and navigate to: `http://YOUR_SERVER_IP`
   - Default credentials:
     - Username: `admin@admin.net`
     - Password: `admin`
   - **IMPORTANT**: Change the password immediately after first login!

## What Gets Installed

The script installs and configures:

- **Node.js 20.x** (LTS version)
- **Yarn** package manager
- **Redis** server (for session management)
- **Build tools** and system dependencies
- **Xen Orchestra** from the official GitHub repository
- **systemd service** for automatic startup

## Port Configuration

- **Port 80 (HTTP)**: Configured and ready to use
- **Port 443 (HTTPS)**: Requires manual SSL certificate configuration

## Enabling HTTPS (Port 443)

To enable HTTPS support:

1. Obtain SSL certificates (e.g., using Let's Encrypt):
```bash
sudo apt-get install certbot
sudo certbot certonly --standalone -d your-domain.com
```

2. Edit the configuration file:
```bash
sudo nano /opt/xen-orchestra/packages/xo-server/.xo-server.toml
```

3. Uncomment and configure the HTTPS section:
```toml
[https]
  listen = [
    { port = 443, cert = '/etc/letsencrypt/live/your-domain.com/fullchain.pem', key = '/etc/letsencrypt/live/your-domain.com/privkey.pem' }
```

4. Restart the service:
```bash
sudo systemctl restart xo-server
```

## Service Management

### Check Service Status
```bash
sudo systemctl status xo-server
```

### View Live Logs
```bash
sudo journalctl -u xo-server -f
```

### Restart Service
```bash
sudo systemctl restart xo-server
```

### Stop Service
```bash
sudo systemctl stop xo-server
```

### Start Service
```bash
sudo systemctl start xo-server
```

## Updating Xen Orchestra

To update to the latest version:

```bash
cd /opt/xen-orchestra
sudo systemctl stop xo-server
sudo -u xo git pull
sudo -u xo yarn install --ignore-engines
sudo -u xo yarn build
sudo systemctl start xo-server
```

## Troubleshooting

### Service Won't Start

Check the logs for errors:
```bash
sudo journalctl -u xo-server -n 100
```

Common issues:
- Redis not running: `sudo systemctl status redis-server`
- Port already in use: Check if another service is using port 80
- Permission issues: Ensure `/opt/xen-orchestra` is owned by user `xo`

### Cannot Access Web Interface

1. Check if the service is running:
```bash
sudo systemctl status xo-server
```

2. Verify the port is listening:
```bash
sudo netstat -tulpn | grep 80
```

3. Check firewall rules:
```bash
sudo ufw status
```

4. Verify server IP address:
```bash
hostname -I
```

### Redis Connection Issues

Ensure Redis is running:
```bash
sudo systemctl status redis-server
sudo systemctl restart redis-server
```

### Build Errors

If you encounter build errors during installation:

1. Ensure you have enough disk space:
```bash
df -h
```

2. Check Node.js version (should be 20.x):
```bash
node --version
```

3. Clear npm cache and retry:
```bash
sudo -u xo yarn cache clean
cd /opt/xen-orchestra
sudo -u xo yarn install --ignore-engines
```

## File Locations

- **Installation Directory**: `/opt/xen-orchestra`
- **Configuration File**: `/opt/xen-orchestra/packages/xo-server/.xo-server.toml`
- **systemd Service**: `/etc/systemd/system/xo-server.service`
- **Logs**: `journalctl -u xo-server`

## Security Recommendations

1. **Change Default Password**: Immediately after first login
2. **Enable HTTPS**: Configure SSL certificates for encrypted connections
3. **Firewall**: Ensure only necessary ports are open
4. **Regular Updates**: Keep Xen Orchestra and the system updated
5. **Backup Configuration**: Regularly backup your `.xo-server.toml` file

## Performance Optimization

For production environments:

1. **Increase Redis memory** (edit `/etc/redis/redis.conf`):
```
maxmemory 256mb
maxmemory-policy allkeys-lru
```

2. **Configure Node.js memory limits** in the systemd service:
```
Environment="NODE_OPTIONS=--max-old-space-size=4096"
```

3. **Enable log rotation** to prevent disk space issues

## Support and Resources

- **Official Documentation**: https://docs.xen-orchestra.com/
- **GitHub Repository**: https://github.com/vatesfr/xen-orchestra
- **Community Forum**: https://xcp-ng.org/forum/

## Important Notes

- This installation method is from source and is NOT officially supported for production use
- For production environments, consider using XOA (Xen Orchestra Appliance)
- The default configuration uses HTTP only - configure HTTPS for production
- Redis is required for session management and must be running

## Uninstallation

To completely remove Xen Orchestra:

```bash
sudo systemctl stop xo-server
sudo systemctl disable xo-server
sudo rm /etc/systemd/system/xo-server.service
sudo systemctl daemon-reload
sudo rm -rf /opt/xen-orchestra
sudo userdel -r xo
sudo apt-get remove --purge redis-server
```

## License

Xen Orchestra is licensed under AGPL3. See the official repository for details.
