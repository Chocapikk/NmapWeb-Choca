import os
import nmap

from flask import Flask, render_template, send_file, request

app = Flask(__name__)

@app.route("/", methods=["GET"])
def start():
    return render_template('index.html')

@app.route("/scan_results/<filename>")
def get_file(filename):
    try:
        path = f"./scan_results/{filename}"
        return send_file(path, as_attachment=True)
    except:
        return "<b>Error to read the file !!!</b>"    
    
@app.route("/scan", methods=["POST"])
def scanner():
    try:
        ip = request.form.get('ip')
        interval = request.form.get('interval')
        rescan = request.form.get('rescan')
        nm = nmap.PortScanner()
        scan_path = "scan_results"
        file = f"{ip}-{interval}_scan.txt"
        output_file = f"{scan_path}/{file}"
        if file in os.listdir(scan_path) and not rescan:
            output = open(output_file,'r').read()
        else:
            nl = '\n'
            nm.scan(ip, interval, arguments='-sV -sT -T5 -Pn')
            output = f"Host: {ip}{nl}"
            output += f"State: {nm[ip].state()}{nl}"
            output += f"Command: {nm.command_line()}{nl}"
            for proto in nm[ip].all_protocols():
                lport = nm[ip][proto].keys()
                for port in lport:
                    state = nm[ip][proto][port]['state']
                    name = nm[ip][proto][port]['name']
                    product = nm[ip][proto][port]['product']
                    version = nm[ip][proto][port]['version']
                    service = f"({name}) {product} {version}"
                    output += "Port: {}\tState: {}\tService: {}\n".format(f"{port}/{proto}", state, service)
            with open(output_file, 'w') as f:
                f.write(output)

        return render_template('scan.html', ip=ip, output=output, file=output_file)
    except KeyError:
        return "<b>Please check your arguments</b>"


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=7777, debug=True)
