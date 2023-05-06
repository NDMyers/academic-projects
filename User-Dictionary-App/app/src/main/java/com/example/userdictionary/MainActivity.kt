package com.example.userdictionary

import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.userdictionary.databinding.ActivityMainBinding

// TODO: for word make "enter" on keyboard submit instead of new line
// TODO: increase definition font size for readability      **DONE**
// TODO: able to change colors?
// TODO: Left side tab for full view of every word
// TODO: download words to share


class MainActivity : AppCompatActivity() {
    private lateinit var recyclerView : RecyclerView
    private lateinit var foodList : ArrayList<Food>
    private lateinit var foodAdapter : FoodAdapter
    private lateinit var binding : ActivityMainBinding
    private var isInFront = false

    private fun hideMyKeyboard() {
        val view = this.currentFocus
        if (view != null) {
            val hideMe = getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
            hideMe.hideSoftInputFromWindow(view.windowToken,0)
        }
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN)
    }

    // Makes the back button refresh the page in the case where user deletes
    // word then goes back to main screen
    override fun onRestart() {
        super.onRestart()
        finish()
        overridePendingTransition(0, 0);
        startActivity(intent)
        overridePendingTransition(0, 0);
    }

    override fun onCreate(savedInstanceState : Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        val view = binding.root
        setContentView(view)
        //setContentView(R.layout.activity_main)

        // ** DATABASE SECTION
        // Create SQlite database helper
        var helper = MyDBHelper(applicationContext)
        // Create readable database from helper
        var db = helper.readableDatabase
        // Creates database cursor
        var rs = db.rawQuery("SELECT * FROM WORDS", null)

        // ** RECYCLER VIEW SECTION
        recyclerView = findViewById(R.id.recyclerView)
        recyclerView.setHasFixedSize(true)
        recyclerView.layoutManager = LinearLayoutManager(this)

        foodList = ArrayList()

//      foodList.add(Food(R.drawable.pizza,"Pizza"))

        foodAdapter = FoodAdapter(foodList)
        recyclerView.adapter = foodAdapter

        // Goes into detailed word/definition view with delete button inside
        foodAdapter.onItemClick = {
            val intent = Intent(this, DetailedActivity::class.java)
            intent.putExtra("food",it)
            startActivity(intent)
        }

        // Gets all previous entries in DB and puts them back
        if (rs.moveToFirst()) {
            while (!rs.isAfterLast) {
                binding.editText1.setText(rs.getString(1))
                binding.editText2.setText(rs.getString(2))
                var test1 = binding.editText1.text.toString()
                var test2 = binding.editText2.text.toString()
                foodList.add(Food(test1, test2))
                rs.moveToNext()
                binding.editText1.setText("")
                binding.editText2.setText("")
            }
        }

        // When Input or Enter button is clicked
        binding.button.setOnClickListener {
            // Checks if user inputs nothing for word or definition
            if ((binding.editText1.text.toString() != "") && (binding.editText2.text.toString() != "")) {
                var cv = ContentValues()
                // Puts information from text boxes into cv
                var unameStr = binding.editText1.text.toString()
                cv.put("WORD",binding.editText1.text.toString())
                cv.put("DEF",binding.editText2.text.toString())
                // Inserts cv information into database
                db.insert("WORDS",null,cv)
    //            if ((unameStr == "Pizza") or (unameStr == "pizza")) {
    //                foodList.add(Food(R.drawable.pizza,binding.editText1.text.toString()))
    //            }

                foodList.add(Food(binding.editText1.text.toString(),binding.editText2.text.toString()))

                // Resets text boxes in app for next input
                binding.editText1.setText("")
                binding.editText2.setText("")
                hideMyKeyboard()
            }

            // Error message in case they do
            else {
                Toast.makeText(applicationContext,"Cannot insert blank word/definition",Toast.LENGTH_LONG).show()
            }
        }

    }
}