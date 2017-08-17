#include <tlswhelper.h>

namespace tlsw{
        
    void
    stripString(char* in,char* out)
    {
        /*
            Strips the string of all symbols and adds null terminator.

            @param:
                in  - (char *) original string (ensure same size)
                out - (char *) new string (ensure same size)
        */
        int i = 0, c = 0;
        for(; i < strlen(in); i++)
        {
            if (isalnum(in[i]))
            {
                out[c] = in[i];
                c++;
            }
        }
        out[c] = '\0';
    }

    void
    getTime(char* out)
    {
        /*
            Gets the time and puts the correct format in out
            (24 hour, localtime)
    
            @param:
                out  - (char*) The string that will get outputted to
                        Make sure at least buff is 150 in size
        */
     
        time_t currenttime;
        struct tm * timeinfo;
        currenttime = time(NULL);
        timeinfo    = localtime(&currenttime);
        strftime(out, 150, "[%H:%M:%S]", timeinfo);
    }
    
    void
    lower(char* in)
    {
        /*
            Converts in string to all lowercase
    
            @param:
                in - (char*) The string to convert
        */
        for ( ; *in; ++in) *in = tolower(*in); 
    }

    
    int
    getLine(char* message, size_t buffsize)
    {
        /*
            Gets the current line from the input.
     
            @param:
                message  - (char*) The message we want to load into
                buffsize - (size_t) The size of the message buffer 
        */
        int characters;
        if((characters = getline(&message,&buffsize,stdin)) < 0)
        {
            perror("Getline faild");
            exit(EXIT_FAILURE);
        }
        return characters;
    }
}
