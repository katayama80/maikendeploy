import React from 'react';

const StarRating = ({ rating, setRating }) => {
  return (
    <div>
      {[...Array(5)].map((_, index) => {
        index += 1;
        return (
          <span
            key={index}
            className={index <= rating ? "star on" : "star off"}
            onClick={() => setRating(index)}
          >
            &#9733;
          </span>
        );
      })}
    </div>
  );
};

export default StarRating;