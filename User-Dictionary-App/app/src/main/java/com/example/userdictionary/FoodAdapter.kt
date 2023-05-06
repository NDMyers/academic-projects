package com.example.userdictionary

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.ImageView
import androidx.recyclerview.widget.RecyclerView

class FoodAdapter(private val foodList:ArrayList<Food>)
    : RecyclerView.Adapter<FoodAdapter.FoodViewHolder>(){

//    class FoodViewHolder(itemView:View) : RecyclerView.ViewHolder(itemView) {
//        val imageView : ImageView = itemView.findViewById(R.id.imageView)
//        val textView : TextView = itemView.findViewById(R.id.textView)
//
//    }

        var onItemClick : ((Food) -> Unit)? = null

        class FoodViewHolder(itemView:View) : RecyclerView.ViewHolder(itemView) {
        val wordView : TextView = itemView.findViewById(R.id.wordView)
        val defView : TextView = itemView.findViewById(R.id.defView)

    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): FoodViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.each_item, parent, false)
        return FoodViewHolder(view)
    }

    override fun getItemCount(): Int {
        return foodList.size
    }

//    override fun onBindViewHolder(holder: FoodViewHolder, position: Int) {
//        val food = foodList[position]
//        holder.imageView.setImageResource(food.image)
//        holder.textView.text = food.name
//    }

    override fun onBindViewHolder(holder: FoodViewHolder, position: Int) {
        val food = foodList[position]
        holder.wordView.text = food.word
        holder.defView.text = food.def

        holder.itemView.setOnClickListener {
            onItemClick?.invoke(food)
        }
    }


}