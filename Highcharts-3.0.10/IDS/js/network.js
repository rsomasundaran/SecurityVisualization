List = [];

//Datatable and Detail table div
var main_area_id;

var show_buttons = function () {
    change_button_visibility("inline-block");
    $('.dropdown-toggle').dropdown();

}



var view_graph = function () {
    var main = document.getElementById('rm-for-graph');
    main_area_id = document.getElementById('main_area');
    if (main_area_id != null)
        main.removeChild(main_area_id);
    var title = document.getElementById('section_title');
    title.innerHTML = "Graph Visualization";
    show_buttons();
}

function change_button_visibility(value) {
    var div = document.getElementById('show_buttons');
    var divs = div.getElementsByTagName('div');
    for (var i = 0; i < divs.length; i++)
        divs[i].style.display = value;
}

var display_tables = function () {
    change_button_visibility("none");
    var main = document.getElementById('rm-for-graph');
    document.getElementById('section_title').innerHTML = "Events Overview";
    main.appendChild(main_area_id);

}

var oTable;

var progress = setInterval(function () {
    var $bar = $('.bar');

    if ($bar.width() >= 400) {
        clearInterval(progress);
        $('.progress').removeClass('active');
    } else {
        $bar.width($bar.width() + 80);
    }
    $bar.text($bar.width() / 4 + "%");
}, 800);


function hex2a(hexx) {
    var hex = hexx.toString(); //force conversion
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}

//Tag used to access the tcp flags in createTable and clear_tcp_fields
var tag = {
                    0: 'tcp_fin',
                    1: 'tcp_syn',
                    2: 'tcp_rst',
                    3: 'tcp_psh',
                    4: 'tcp_ack',
                    5: 'tcp_urg',
                    6: 'tcp_r0',
                    7: 'tcp_r1'
                };


function clear_tcp_fields() {
    var shifter_iterator = 0;
    document.getElementById('tcp_sport').innerHTML = "---";
    document.getElementById('tcp_dport').innerHTML = "---";
    document.getElementById('tcp_seq').innerHTML   = "---";
    document.getElementById('tcp_ackn').innerHTML  = "---";
    document.getElementById('tcp_off').innerHTML   = "---";
    document.getElementById('tcp_res').innerHTML   = "---";
    document.getElementById('tcp_win').innerHTML   = "---";
    document.getElementById('tcp_urp').innerHTML   = "---";
    document.getElementById('tcp_csum').innerHTML  = "---";
    while (shifter_iterator < 8) {
        document.getElementById(tag[shifter_iterator]).innerHTML = "---";
        shifter_iterator++;
    }
}

var createTable = function (fullData, callback) {
    var request = $.getJSON('event_log.json', function (data) {
        $.each(data, function (index, value) {
            fullData[index] = [];
            fullData[index] = value;
            List[index] = [];
            List[index].push(index + 1);
            List[index].push(value.sig_priority);
            var myDate = new Date(value.timestamp);
            myDate = moment(myDate).format('YYYY-MM-DD HH:mm:ss');
            List[index].push(myDate);
            List[index].push(numToDot(value.ip_src));
            List[index].push(FindPortTypes(value, true));
            List[index].push(numToDot(value.ip_dst));
            List[index].push(FindPortTypes(value, false));
            List[index].push(value.sig_name);

        });
        oTable = $('#example').dataTable({
            "sDom": "<'row'<'span8'l><'span8'f>r>t<'row'<'span8'i><'span8'p>>",
            "aaData": List,
            "aoColumns": [{
                "sTitle": "Id"
            }, {
                "sTitle": "Pri"
            }, {
                "sTitle": "Data/Time"
            }, {
                "sTitle": "Src IP"
            }, {
                "sTitle": "SPort"
            }, {
                "sTitle": "Dst IP"
            }, {
                "sTitle": "DPort"
            }, {
                "sTitle": "Event Message"
            }, ]
        });

        $("#example tbody").on('click', 'tr', function (event) {
            packetLog = oTable.fnGetData(this);
            var fullLog = fullData[packetLog[0] -1];
            console.log("In click event");
            document.getElementById('src_ip').innerHTML = packetLog[3];
            document.getElementById('dst_ip').innerHTML = packetLog[5];
            document.getElementById('ip_ver').innerHTML = fullLog.ip_ver;
            document.getElementById('ip_ver').innerHTML = fullLog.ip_ver;
            document.getElementById('ip_hl').innerHTML = fullLog.ip_hlen;
            document.getElementById('ip_tos').innerHTML = fullLog.ip_tos;
            document.getElementById('ip_tos').innerHTML = fullLog.ip_tos;
            document.getElementById('ip_len').innerHTML = fullLog.ip_tos;
            document.getElementById('ip_id').innerHTML = fullLog.ip_id;
            document.getElementById('ip_flags').innerHTML = fullLog.ip_flags;

            document.getElementById('ip_off').innerHTML = fullLog.ip_off;
            document.getElementById('ip_ttl').innerHTML = fullLog.ip_ttl;
            document.getElementById('ip_csum').innerHTML = fullLog.ip_csum;
            if (fullLog.data_payload != null) {
                document.getElementById('packet_data').innerHTML = fullLog.data_payload;
                document.getElementById('ascii_data').innerHTML = hex2a(fullLog.data_payload);
            }

            if (fullLog.ip_proto == 1) {
                //ICMP
                clear_tcp_fields();

            } else if (fullLog.ip_proto == 6) {
                //Currently just show for TCP
                document.getElementById('tcp_sport').innerHTML = fullLog.tcp_sport;
                document.getElementById('tcp_dport').innerHTML = fullLog.tcp_dport;
                document.getElementById('tcp_seq').innerHTML   = fullLog.tcp_seq;
                document.getElementById('tcp_ackn').innerHTML  = fullLog.tcp_ack;
                document.getElementById('tcp_off').innerHTML   = fullLog.tcp_off;
                document.getElementById('tcp_res').innerHTML   = fullLog.tcp_res;
                document.getElementById('tcp_win').innerHTML   = fullLog.tcp_win;
                document.getElementById('tcp_urp').innerHTML   = fullLog.tcp_urp;
                document.getElementById('tcp_csum').innerHTML  = fullLog.tcp_csum;

                var flags = parseInt(fullLog.tcp_flags);
                console.log("flags in dec: " + flags);
                console.log("flags in log: " + fullLog.tcp_flags);
                var shifter_iterator = 0;
                var mask = 1;
                
                while (shifter_iterator < 8) {
                    if (flags & (mask << shifter_iterator))
                        document.getElementById(tag[shifter_iterator]).innerHTML = 1;
                    else
                        document.getElementById(tag[shifter_iterator]).innerHTML = 0;
                    shifter_iterator++;


                }


            } else if (fullLog.ip_proto == 17) {
                //UDP
            }


        });

    });

    request.done(function () {
        window.List = List;
        callback(List);
    });

}

function storeData() {
    var List = [];
    $.getJSON('event_log.json', function (data) {
        $.each(data, function (index, value) {
            List[index] = [];
            List[index].push(index + 1);
            List[index].push(value.sig_priority);
            var myDate = new Date(value.timestamp);
            myDate = moment(myDate).format('YYYY-MM-DD HH:mm:ss');
            List[index].push(myDate);
            List[index].push(numToDot(value.ip_src));
            List[index].push(FindPortTypes(value, true));
            List[index].push(numToDot(value.ip_dst));
            List[index].push(FindPortTypes(value, false));
            List[index].push(value.sig_name);
        });
        return data;
    });
}

function draw_graph(graphType) {
    var dates = [];
    var element = [];
    var data = []

    for (var i = 0; i < List.length; i++) {
        timestamp = List[i][2];
        timestamp = timestamp.slice(0, 10);
        // 2014-04-07 01:53:13
        if (element[timestamp]) {
            element[timestamp] = element[timestamp] + 1;
        } else {
            element[timestamp] = 1;
            dates.push(timestamp);
        }
    }

    var data;
    dates.forEach(function (date) {
        data.push(element[date]);
    });
    var chart = document.getElementById("high_chart");
    chart.className = "chart";

    var d = $.getJSON('chart_data/' + graphType + '.json', function (graphdata) {
        graphdata.xAxis.categories = dates;
        graphdata.series[0].data = data;
        $('#high_chart').highcharts(graphdata);
    });
}
