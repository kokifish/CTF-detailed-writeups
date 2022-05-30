// author: github.com/kokifish
#include <cstring>
#include <iostream>

using namespace std;

int labyrinth_ori[676] = {
    1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 3, 0, 1, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0,
    0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0,
    1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0,
    0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
    0, 0, 0, 4, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 3, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0,
    0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1,
    0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1,
    1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0,
    1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1,
    0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 3, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0,
    0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 4, 0, 0};


int labyrinth[3][15][15] = {
    {
        {1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},  // map 0 line 0: x=0
        {1, 1, 1, 1, 1, 0, 3, 0, 1, 0, 0, 0, 0, 0, 0},  // s
        {1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0},  // s
        {1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0},  // s
        {1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0},  // s
        {1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0},  // s
        {1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0},  // s
        {1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0},  // s
        {1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0},  // ddddddds
        {1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0},  // arrive at 4
        {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},  //
        {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},  //
        {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},  //
        {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},  //
        {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},  //
    },                                                  // sssssssddddddds
    {
        {1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},  // map 1 line 0: x=0
        {1, 1, 0, 3, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0},  // s
        {1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0},  // s
        {1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0},  // s
        {1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0},  // s
        {1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0},  // s
        {1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0},  // s
        {1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0},  // s
        {1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0},  // s
        {1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0},  // s
        {1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0},  // s
        {1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0},  // dddddddddds
        {1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0},  // arrive at 4
        {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},  //
        {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},  //
    },                                                  // ssssssssssdddddddddds
    {
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},  // map 2 line 0: x=0
        {0, 3, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},  // dds
        {0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0},  // s   // dds
        {0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0},  // ddw // s
        {0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0},  // s
        {0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0},  // s
        {0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0},  // s
        {0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0},  // s
        {0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0},  // ddds
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0},  // s
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0},  // s
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0},  // s
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0},  // ddds
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},  // s
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0},
    }};  // ddssddwddssssssdddssssdddss
// sssssssdddddddsssssssssssddddddddddsddssddwddssssssdddssssdddss    // enter a ESC here
void preprocessing() {  // transfer the original labyrinth to a readable form
    for (int i = 0; i < 675; ++i) {
        if (i % 225 == 0) {
            cout << "{";
        }
        if (i % 15 == 0) {
            cout << "\n{" << labyrinth_ori[i];
        } else {
            cout << ", " << labyrinth_ori[i];
        }
        if ((i + 1) % 15 == 0) {
            cout << "},";
        }
        if ((i + 1) % 225 == 0) {
            cout << "},\n";
        }
    }
}

int labyrinth_idx;
int x, y;
void ini() {
    labyrinth_idx = 0;  // corresponding to dword_10011D10
}
int ini_xy() {
    int i, j;
    bool result;
    for (i = 0;; ++i) {
        result = i < 15;
        if (i >= 15) {
            break;
        }
        for (j = 0; j < 15; ++j) {
            if (labyrinth_ori[225 * labyrinth_idx + 15 * i + j] == 3) {
                x = i;
                y = j;
                break;
            }
            return result;
        }
    }
    return result;
}
int movRight() {
    if (y != 14) {
        if (labyrinth_ori[225 * labyrinth_idx + 1 + 15 * x + y] == 1) {
            labyrinth_ori[225 * labyrinth_idx + 1 + 15 * x + y] = 3;
            labyrinth_ori[225 * labyrinth_idx + 15 * x + y] = 1;
        } else if (labyrinth_ori[225 * labyrinth_idx + 1 + 15 * x + y] == 4) {
            return 1;
        }
    }
    return 0;
}
int movDown() {
    if (x != 14) {
        if (labyrinth_ori[225 * labyrinth_idx + 15 + 15 * x + y] == 1) {
            labyrinth_ori[225 * labyrinth_idx + 15 + 15 * x + y] = 3;
            labyrinth_ori[225 * labyrinth_idx + 15 * x + y] = 1;
        } else if (labyrinth_ori[225 * labyrinth_idx + 15 + 15 * x + y] == 4) {
            return 1;
        }
    }
    return 0;
}
int movUp() {
    if (x) {
        if (labyrinth_ori[225 * labyrinth_idx - 15 + 15 * x + y] == 1) {
            labyrinth_ori[225 * labyrinth_idx - 15 + 15 * x + y] = 3;
            labyrinth_ori[225 * labyrinth_idx + 15 * x + y] = 1;
        } else if (labyrinth_ori[225 * labyrinth_idx - 15 + 15 * x + y] == 4) {
            return 1;
        }
    }
    return 0;
}
int movLeft() {
    if (y) {
        if (labyrinth_ori[225 * labyrinth_idx - 1 + 15 * x + y] == 1) {
            labyrinth_ori[225 * labyrinth_idx - 1 + 15 * x + y] = 3;
            labyrinth_ori[225 * labyrinth_idx + 15 * x + y] = 1;
        } else if (labyrinth_ori[225 * labyrinth_idx - 1 + 15 * x + y] == 4) {
            return 1;
        }
    }
    return 0;
}
int labyrinth_main() {
    char action;  // action extracted from v4 // corresponding to v0
    int v2;       // record move action return value
    int v3 = 0;   // v4's index
    char v4[512];
    memset(v4, 0, 512);
    scanf("%s", v4);
    while (1) {
        do {
            v2 = 0;
            // here call a function: if 4(exit) found in a map, record x,y and return true
            // else return false
            ini_xy();  // ini x, y
            action = v4[v3];
            cout << "[DEBUG] action=" << (int)action << " v3=" << v3 << endl;
            if (action == 'd') {  // move right
                v2 = movRight();
            } else if (action == 's') {  // move down
                v2 = movDown();
            } else if (action == 'w') {  // move up
                v2 = movUp();
            } else if (action == 'a') {
                v2 = movLeft();
            } else if (action == '\x1B') {  // ESC
                return -1;
            } else {
                cout << "[WARNING] To avoid Segmentation fault (core dumped) ERROR, break"
                     << endl;
                break;
            }
            ++v3;
        } while (v2 != 1);
        if (labyrinth_idx == 2) {
            break;
        }
        cout << "[DEBUG] labyrinth_idx=" << labyrinth_idx << endl;
        ++labyrinth_idx;
    }
    cout << "success! the flag is flag{md5(your input)}" << endl;
    return 1;
}
int main() {
    int ret_value;
    void ini();
    do {
        ret_value = labyrinth_main();
    } while (ret_value != 1 && ret_value != -1);
    return 0;
}
