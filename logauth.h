/**
 * @file  logauth.h
 * @brief
 *
 * bla
 */

#ifndef LOGAUTH_H
#define LOGAUTH_H

/* This is the event class.
Events are Objects with a log message.
*/
class EVENT{
	public:
	std::string log;

	EVENT(std::string l){
		log = l;
	}
	std::string getLog(){
		return log;
	}
};


/* This method tries to retrieve the next event.
When implemented correct, it should return an pointer to an event OR NULL when no event happened.
Here with 'new' we allocate memory, so it has to be freed later.
*/
static EVENT* getNextEvent(){
	std::string line = "a simple mock event";
	return new EVENT(line);
}


#endif /* LOGAUTH_H */
