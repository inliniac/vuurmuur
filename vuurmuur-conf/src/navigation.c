/***************************************************************************
 *   Copyright (C) 2003-2006 by Victor Julien                              *
 *   victor@nk.nl                                                          *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/
 
#include "main.h"


/*	nav_field_comment

	Needs the field label to be "comment".

	This is a special function because it needs to handle a edit field

	F5,F6,F10,F12 or ESC make the function return -1, all others return 0.
*/
int
nav_field_comment(const int debuglvl, FORM *form, int key)
{
	switch(key)
	{
		case 9:
			return(-1);
		
		case KEY_F(5):
		case KEY_F(6):
		case KEY_F(10):
		case KEY_F(12):
		case 27: //esc:

			form_driver(form, REQ_NEXT_FIELD); // this is to make sure the field is saved
			return(-1);
		
		case 32: // space
			form_driver(form, key);
			break;
		case 10: // enter
			// go line-by-line trough the field, when reaching the end, go to next field.
			if(form_driver(form, REQ_NEXT_LINE) < 0)
			{
				form_driver(form, REQ_NEXT_FIELD);
			}
			form_driver(form, REQ_BEG_LINE);
			break;
		case KEY_DOWN:
			// move down in the field, until we reach the end,
			// them move to the next field
			if(form_driver(form, REQ_DOWN_CHAR) < 0)
			{
				form_driver(form, REQ_NEXT_FIELD);
				form_driver(form, REQ_BEG_LINE);
			}
			break;
		case KEY_UP:
			// move up in the field, until we reach the end,
			// them move to the previous field
			if(form_driver(form, REQ_UP_CHAR) < 0)
			{
				form_driver(form, REQ_PREV_FIELD);
				form_driver(form, REQ_BEG_LINE);
			}
			break;
		case KEY_RIGHT:
			if(form_driver(form, REQ_RIGHT_CHAR) < 0)
			{
				if(form_driver(form, REQ_DOWN_CHAR) < 0)
					form_driver(form, REQ_BEG_FIELD);
				else
					form_driver(form, REQ_BEG_LINE);
			}
			break;
		case KEY_LEFT:
			if(form_driver(form, REQ_LEFT_CHAR) < 0)
			{
				if(form_driver(form, REQ_UP_CHAR) < 0)
					form_driver(form, REQ_END_FIELD);
				else
					form_driver(form, REQ_END_LINE);
			}
			break;
		case 127: // backspace
		case KEY_BACKSPACE:
			form_driver(form, REQ_PREV_CHAR);
			form_driver(form, REQ_DEL_CHAR);
			break;
		case KEY_DC: // delete
			form_driver(form, REQ_DEL_CHAR);
			break;
		case KEY_HOME: // doesn't seem to work in my kde (3.1.2) setup
			form_driver(form, REQ_BEG_LINE);
			break;
		case KEY_END:
			form_driver(form, REQ_END_LINE);
			break;
		default:
			// If this is a normal character, it gets printed
			form_driver(form, key);
			break;
	}

	return(0);
}


int
nav_field_simpletext(const int debuglvl, FORM *form, int key)
{
	int	ch = 0;

	switch(key)
	{
		case 9:		/* tab */
			return(-1);
		
		case KEY_F(5):	/* f5  */
		case KEY_F(6):	/* f6  */
		case KEY_F(10):	/* f10 */
		case KEY_F(12): /* f12 for help */
		case 27:	/* esc */

			form_driver(form, REQ_NEXT_FIELD); // this is to make sure the field is saved
			form_driver(form, REQ_PREV_FIELD); /* But we don't want to move down */
			return(-1);
		
		case 32: // space
			form_driver(form, key);
			break;
		case KEY_DOWN:
		case 10: // enter
			form_driver(form, REQ_NEXT_FIELD);
			form_driver(form, REQ_BEG_LINE);
			break;
		case KEY_UP:
			form_driver(form, REQ_PREV_FIELD);
			form_driver(form, REQ_BEG_LINE);
			break;
		case KEY_RIGHT:
			if(form_driver(form, REQ_RIGHT_CHAR) < 0)
			{
				ch = form_driver(form, REQ_SCR_FCHAR);
/*
				if(ch == E_REQUEST_DENIED)
					status_print(status_win, "form_driver (right): %d, E_REQUEST_DENIED", ch);
				else if(ch == E_INVALID_FIELD)
					status_print(status_win, "form_driver (right): %d, E_INVALID_FIELD", ch);
				else if(ch == E_UNKNOWN_COMMAND)
					status_print(status_win, "form_driver (right): %d, E_UNKNOWN_COMMAND", ch);
				else if(ch == E_NOT_POSTED)
					status_print(status_win, "form_driver (right): %d, E_NOT_POSTED", ch);
				else if(ch == E_BAD_STATE)
					status_print(status_win, "form_driver (right): %d, E_BAD_STATE", ch);
				else if(ch == E_BAD_ARGUMENT)
					status_print(status_win, "form_driver (right): %d, E_BAD_ARGUMENT", ch);
				else if(ch == E_SYSTEM_ERROR)
					status_print(status_win, "form_driver (right): %d, E_SYSTEM_ERROR", ch);
				else if(ch == E_OK)
					status_print(status_win, "form_driver (right): %d, E_OK", ch);
				else
					status_print(status_win, "form_driver (right): %d, unknown", ch);
			*/
			}

			break;

		case KEY_LEFT:
			if(form_driver(form, REQ_LEFT_CHAR) < 0)
			{
				ch = form_driver(form, REQ_SCR_BCHAR);
/*
				if(ch == E_REQUEST_DENIED)
					status_print(status_win, "form_driver (left): %d, E_REQUEST_DENIED", ch);
				else if(ch == E_INVALID_FIELD)
					status_print(status_win, "form_driver (left): %d, E_INVALID_FIELD", ch);
				else if(ch == E_UNKNOWN_COMMAND)
					status_print(status_win, "form_driver (left): %d, E_UNKNOWN_COMMAND", ch);
				else if(ch == E_NOT_POSTED)
					status_print(status_win, "form_driver (left): %d, E_NOT_POSTED", ch);
				else if(ch == E_BAD_STATE)
					status_print(status_win, "form_driver (left): %d, E_BAD_STATE", ch);
				else if(ch == E_BAD_ARGUMENT)
					status_print(status_win, "form_driver (left): %d, E_BAD_ARGUMENT", ch);
				else if(ch == E_SYSTEM_ERROR)
					status_print(status_win, "form_driver (left): %d, E_SYSTEM_ERROR", ch);
				else if(ch == E_OK)
					status_print(status_win, "form_driver (left): %d, E_OK", ch);
				else
					status_print(status_win, "form_driver (left): %d, unknown", ch);
*/
			}

			//status_print(status_win, "form_driver (left): %d", ch);
			break;

		case 127: // backspace
		case KEY_BACKSPACE:
			form_driver(form, REQ_PREV_CHAR);
			form_driver(form, REQ_DEL_CHAR);
			break;
		case KEY_DC:
			form_driver(form, REQ_DEL_CHAR);
			break;
		case KEY_HOME: // doesn't seem to work in my kde (3.1.2) setup
			form_driver(form, REQ_BEG_LINE);
			break;
		case KEY_END:
			form_driver(form, REQ_END_LINE);
			break;
		default:
			// If this is a normal character, it gets printed
			form_driver(form, key);
			break;
	}

	return(0);
}


/*

*/
int
nav_field_yesno(const int debuglvl, FORM *form, int key)
{
	switch(key)
	{
		case 32: // space
		{
			FIELD *cur;
			cur = current_field(form);

			if(strncasecmp(field_buffer(cur, 0), STR_YES, StrLen(STR_YES)) == 0)
			{
				set_field_buffer_wrap(debuglvl, cur, 0, STR_NO);
			}
			else
			{
				set_field_buffer_wrap(debuglvl, cur, 0, STR_YES);
			}
			break;
		}
		case 'y':
		{
			FIELD *cur;
			cur = current_field(form);

			if(strncasecmp(field_buffer(cur, 0), STR_NO, StrLen(STR_NO)) == 0)
			{
				set_field_buffer_wrap(debuglvl, cur, 0, STR_YES);
			}
			break;
		}
		case 'n':
		{
			FIELD *cur;
			cur = current_field(form);

			if(strncasecmp(field_buffer(cur, 0), STR_YES, StrLen(STR_YES)) == 0)
			{
				set_field_buffer_wrap(debuglvl, cur, 0, STR_NO);
			}
			break;
		}
		default:
			return(-1);
	}
	return(0);
}


int
nav_field_toggleX(const int debuglvl, FORM *form, int key)
{
	FIELD	*cur = NULL;
	
	if(!form)
		return(-1);
	
	if(!(cur = current_field(form)))
		return(-1);

	switch(key)
	{
		case 32: // space
		{
			if(strncasecmp(field_buffer(cur, 0), "X", 1) == 0)
			{
				set_field_buffer_wrap(debuglvl, cur, 0, " ");
			}
			else
			{
				set_field_buffer_wrap(debuglvl, cur, 0, "X");
			}

			break;
		}
		case 'y':
		{
			if(strncasecmp(field_buffer(cur, 0), " ", 1) == 0)
			{
				set_field_buffer_wrap(debuglvl, cur, 0, "X");
			}

			break;
		}
		case 'n':
		{
			if(strncasecmp(field_buffer(cur, 0), "X", 1) == 0)
			{
				set_field_buffer_wrap(debuglvl, cur, 0, " ");
			}

			break;
		}
		default:
			return(-1);
	}

	return(0);
}


int
validate_commentfield(const int debuglvl, char *fieldbuffer, regex_t *reg_ex)
{
	size_t	i = 0;

	/* safety */
//	if(!fieldbuffer || !reg_ex)
	if(!fieldbuffer)
	{
		(void)vrprint.error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/* run the regex */
/*
	if(regexec(reg_ex, fieldbuffer, 0, NULL, 0) != 0)
	{
		(void)vrprint.error(-1, "Error", "comment line contains illegal characters.");
		return(-1);
	}
*/
	
	for(i = 0; i < StrMemLen(fieldbuffer); i++)
	{
		if(fieldbuffer[i] == '"')
		{
			(void)vrprint.error(-1, VR_ERR, gettext("the double quote sign \" is not allowed in the commentfield."));
			return(-1);
		}
		else if(fieldbuffer[i] == '%')
		{
			(void)vrprint.error(-1, VR_ERR, gettext("the percent sign is not allowed in the commentfield."));
			return(-1);
		}
	}
	
	return(0);

}
