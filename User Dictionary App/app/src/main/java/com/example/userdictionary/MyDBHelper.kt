package com.example.userdictionary

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

class MyDBHelper(context:Context) : SQLiteOpenHelper(context,"WORDS", null, 1) {
    override fun onCreate(db: SQLiteDatabase?) {
        db?.execSQL("CREATE TABLE WORDS(USERID INTEGER PRIMARY KEY AUTOINCREMENT, WORD TEXT, DEF TEXT)")
//        db?.execSQL("INSERT INTO USERS(UNAME,PWD) VALUES('ndmyers@ucdavis.edu','Theb1gw4ff13dest')")
//        db?.execSQL("INSERT INTO USERS(UNAME,PWD) VALUES('ndm81001@gmail.com','Nikkerish45')")
    }

    override fun onUpgrade(p0: SQLiteDatabase?, p1: Int, p2: Int) {

    }

}