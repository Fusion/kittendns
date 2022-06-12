function nineResponder() {
    return "9.9.9.9";
}

// Thank you WorldTimeAPI! (http://worldtimeapi.org/)
function timeResponder(locale) {
    /* Maybe at some point I'll play with Promises,
       considering I'm not entirely clear whether
       I can run this in a goroutine without consequences.
    */
   var response = null;
    fetch.get("http://worldtimeapi.org/api/timezone/" + locale,
        function(r) {
            if (r.StatusCode == 200) {
                var json = JSON.parse(r.Body);
                response = {"action": Reply, "type": typeTXT, "TTL": 60, "RR": [{"target": json['utc_datetime']}], "Done": true};
            }
        },
        function(e) {
            console.error("Failed: " + e);
        }
    );
    if (response == null)
        return {"action": Reply, "type": typeTXT, "TTL": 60, "RR": [{"target": "Unknown!"}], "Done": true};
    return response;
}

module.exports = {
    nineResponder: nineResponder,
    timeResponder: timeResponder
}
