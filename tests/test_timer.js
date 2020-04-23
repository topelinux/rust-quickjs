import * as std from "std";
import * as os from "os";

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

os_setTimeout(()=> {
    console.log('hi i am trigger');
}, 1000);

