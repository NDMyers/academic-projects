package com.example.userdictionary

import android.annotation.SuppressLint
import android.content.ContentValues
import android.content.Intent
import android.database.Cursor
import android.os.Bundle
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.example.userdictionary.databinding.ActivityDetailedBinding
import kotlinx.coroutines.selects.select

class DetailedActivity : AppCompatActivity() {
    private var isUnedited = true
    private lateinit var binding : ActivityDetailedBinding

    private fun setDefaultView(): Boolean {
        binding.editButton.text = "Edit"
        binding.definition.isEnabled = true
        binding.definition.visibility = View.VISIBLE
        binding.word.isEnabled = true
        binding.word.visibility = View.VISIBLE

        binding.defEdit.isEnabled = false
        binding.defEdit.visibility = View.INVISIBLE
        binding.wordEdit.isEnabled = false
        binding.wordEdit.visibility = View.INVISIBLE

        return false
    }

    private fun setEditView(): Boolean {
        binding.editButton.text = "Finish"
        binding.definition.isEnabled = false
        binding.definition.visibility = View.INVISIBLE
        binding.word.isEnabled = false
        binding.word.visibility = View.INVISIBLE

        binding.defEdit.isEnabled = true
        binding.defEdit.visibility = View.VISIBLE
        binding.wordEdit.isEnabled = true
        binding.wordEdit.visibility = View.VISIBLE

        return true
    }

    @SuppressLint("Range")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_detailed)
        binding = ActivityDetailedBinding.inflate(layoutInflater)
        val view = binding.root
        setContentView(view)

        // Re-enable definition and create boolean check if edit has been clicked or not
        // also refresh any button names to normal values
        var isEditing = setDefaultView()

        // ** DATABASE SECTION
        // Create SQlite database helper
        val helper = MyDBHelper(applicationContext)
        // Create readable database from helper
        val db = helper.readableDatabase
        // Creates database cursor
        //var rs = db.rawQuery("SELECT * FROM WORDS", null)

        // Gets data from main activity from key "food"
        val food = intent.getParcelableExtra<Food>("food")

        // If this data is not null then continue
        if (food!=null) {
            val textView1 : TextView = findViewById(R.id.word)
            val textView2 : TextView = findViewById(R.id.definition)

            // Gets entry ID (USERID in db) for unique matching of entries
            val selectQuery = "SELECT * FROM WORDS WHERE WORD = ? AND DEF = ?"
            var rs = db.rawQuery(selectQuery, arrayOf(food.word,food.def))
            rs.moveToFirst()
            val entryID = rs.getString(0)
            rs.close()

            if (isUnedited) {
                textView1.text = food.word
                textView2.text = food.def
            }

            // Convert to easier variables for database ops
            val word = textView1.text.toString()
            val definition = textView2.text.toString()

            // String Array for db delete arguments
            val argStr : Array<String> = arrayOf(word,definition)

            // Delete button functionality
            binding.delButton.setOnClickListener {
                // database delete command that checks both the word and definition to match
                db.delete("WORDS","WORD = ? and DEF = ?",argStr)
                db.close()
                // Closes up this activity then returns to main activity
                val intent = Intent(this, MainActivity::class.java)
                startActivity(intent)
                finish()
            }

            // Edit button functionality
            binding.editButton.setOnClickListener {
                // IN EDIT MODE, btn becomes "Finish" after clicking
                if (!isEditing) {
                    if (isUnedited) {
                        binding.defEdit.setText(definition) // displays current definition in text box
                        binding.wordEdit.setText(word)
                    }
                    isEditing = setEditView()
                    isUnedited = false
                }
                // ENDS EDIT MODE, btn returns to "Edit" after clicking
                else {
                    // Change definition section
                    val args = ContentValues()
                    val newDef = binding.defEdit.text.toString()
                    val newWord = binding.wordEdit.text.toString()
                    args.put("DEF", newDef)
                    args.put("WORD",newWord)
                    val argStr2 : Array<String> = arrayOf(entryID)
                    db.update("WORDS", args, String.format("USERID = ?"), argStr2)

                    textView1.text = newWord
                    textView2.text = newDef // change visual of definition to new def
                    binding.defEdit.setText(newDef)
                    binding.wordEdit.setText(newWord)
                    isEditing = setDefaultView()
                }
            }
        }
    }
}