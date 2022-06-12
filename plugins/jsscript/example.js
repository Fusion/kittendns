function main(preOrPost, answers, type, name) {
    if (preOrPost == pre) 
        return prefn(type, name);
    return postfn(answers, type, name);
}

function prefn(type, name) {
    // Pulling a TXT record from the magician's hat.
    if (type == typeTXT && name == "magic.example.com.") {
        return {"action": Reply, "type": type, "TTL": 60, "RR": [{"target": "this is a magic record"}], "Done": true};
    }
    // You asked for 'plugintest' but I am going to pretend it was 'test'
    if (type == typeA && name == "plugintest.example.com.") {
        return {"action": Question, "question": {"type": type, "name": "test.example.com."}};
    }
    return toy_dns_fun(type, name);
}

function postfn(answers, type, name) {
    // Rewrite TTL to be 3600 seconds. That is all.
    if (type == typeA && name == "test.example.com.") {
        newAnswers = [];
        for (i = 0; i < answers.length; i++) {
            newAnswers.push({"type": type, "host": answers[i].Header().Name, "ip": answers[i].A.String()});
        }
        return {"action": Rewrite, "type": type, "TTL": 3600, "RR": newAnswers};
    }
    // Alternatively, we could have added a new value using Reply:
    // return {"action": Reply, "type": type, "TTL": 3600, "RR": [{"type": type, "host": name, "ip": "5.6.7.8"}]};
    return {}
}

function toy_dns_fun(type, name) {
    // Replace with "False" to play with toy dns features
    if (false)
        return {}
    var m = require("./plugins/jsscript/extended_example.js");
    if (type == typeA && name == "nine.example.com.") {
        console.log("Plugin information: Querying nine responder");
        var res = m.nineResponder();
        return {"action": Reply, "type": type, "TTL": 60, "RR": [{"host": "nine.example.com", "ip": res}], "Stop": true};
    }
    if (name.endsWith(".time.example.com.")) {
        var bits = name.split(".", 2);
        return m.timeResponder(bits[0]);
    }
    return {}
}
