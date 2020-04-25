import * as std from "std";
import * as os from "os";
import * as QRuffTimer from "QRuffTimer";

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

ru.setTimeout(()=> {
    console.log('hi i am trigger');
}, 1000);

console.log(Object.keys(QRuffTimer));
console.log(QRuffTimer.CONST_16);
QRuffTimer.test_func();
