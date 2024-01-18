// cryptochallenge.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>

extern int run_tests();
extern int call_set1();
extern int call_set2();
extern int call_set3();
extern int call_set4();

int main()
{
    int retcode = 0;
    std::cout << "Hello World!\n";

    run_tests();

    retcode = call_set4();

    std::cout << std::endl;
    system("pause");

    return retcode;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file