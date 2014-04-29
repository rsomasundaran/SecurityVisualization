
var fs = require('fs');
var mysql = require('mysql')
var jsonObject=[];
var lineNumber=0;
var columns=[];

var connection = mysql.createConnection({
  host     : 'localhost',
  user     : 'root',
  password : 'admin'
});

connection.connect(function(err) {
  console.log('Connected');// connected! (unless `err` is set)
});

connection.query("use snort");

var strQuery = "select * from event e natural left join signature sig natural left join iphdr natural left join data natural left join icmphdr natural left join udphdr natural left join tcphdr where e.signature=sig.sig_id and ";

var maxSid;
var lastSid = 0;
var lastCid = 0;

var temp = [];
var numOfEvents;

function writeToJson( rows) {
    var outputFilename = './event_log.json';
    var output = fs.createWriteStream(outputFilename,{'flag': 'a'});
    output.write(JSON.stringify(rows,null,4));
}

function queryRecords(writeToJson) {
    connection.query(strQuery + "(sid > " + lastSid + " or " + "cid > " + lastCid + ")", function(err, rows){
    	if(err){
    		throw err;
            }
    	else{
                 if (rows.length) {
                       numOfEvents = rows.length;
                       writeToJson(rows);
                       console.log("num",numOfEvents);
                       console.log(rows[0]);
                 }
            }
    });
}

queryRecords(writeToJson);

jquery.getJSON('event_log.json', function(data) {
        if(err) {
         throw err;
         }
    console.log("Okay");
});

connection.end();
