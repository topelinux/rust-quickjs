import * as std from "std";
import * as os from "os";
import * as qruff from "qruff";

function test_timer()
{
    var th, i;

    /* just test that a timer can be inserted and removed */
    th = [];
    for(i = 0; i < 3; i++)
        th[i] = os.setTimeout(() => {
            console.log('!!!! cool test');
        }, 2000);
}

//test_timer();

//ru.setTimeout(()=> {
//    console.log('hi i am trigger');
//}, 1000);
//
let setTimeout = qruff.setTimeout;
console.log(Object.keys(qruff));
console.log(qruff.CONST_16);


setTimeout(() => {
    console.log('Coll Qruff timer be triggerd');
}, 2000);
