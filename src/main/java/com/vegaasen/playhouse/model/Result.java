package com.vegaasen.playhouse.model;

import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * @author <a href="vegard.aasen@telenor.com">Vegard Aasen</a>
 */
public final class Result {

    private static final String tabulator = "\t", newLine = "\n";

    private static final String EMPTY = "";
    private Date initiated;
    private long nanoResult;
    private Date finished;
    private String documentUsed;
    private String callingMethod;
    private int numOfIterations;

    private Result() {
    }

    private Result(Builder builder) {
        this.initiated = builder.initiated;
        this.nanoResult = builder.nanoResult;
        this.finished = builder.finished;
        this.documentUsed = builder.documentUsed;
        this.callingMethod = builder.callingMethod;
        this.numOfIterations = builder.numOfIterations;
    }

    public Date getInitiated() {
        return initiated;
    }

    public long getNanoResult() {
        return nanoResult;
    }

    public Date getFinished() {
        return finished;
    }

    public String getDocumentUsed() {
        return documentUsed;
    }

    public String getCallingMethod() {
        return callingMethod;
    }

    public int getNumOfIterations() {
        return numOfIterations;
    }

    public static String generateResultSetString(Result r, int num) {
        if (r != null) {
            StringBuilder builder = new StringBuilder();
            builder.append(String.format("%s)%s", num, tabulator));
            builder.append(r.getInitiated());
            builder.append(tabulator);
            builder.append(r.getFinished());
            builder.append(tabulator);
            builder.append(r.getNumOfIterations());
            builder.append(tabulator);
            builder.append(String.format("%sns%s%sms%s%ss",
                    r.getNanoResult(),
                    tabulator,
                    (double) TimeUnit.NANOSECONDS.toMillis(r.getNanoResult()),
                    tabulator,
                    (double) TimeUnit.NANOSECONDS.toSeconds(r.getNanoResult())
            ));
            builder.append(tabulator);
            builder.append(r.getCallingMethod());
            builder.append(tabulator);
            builder.append(r.getDocumentUsed());
            builder.append(newLine);
            return builder.toString();
        }
        return EMPTY;
    }

    public static String generateResultSetString(List<Result> results) {
        if (results != null && !results.isEmpty()) {
            StringBuilder builder = new StringBuilder();
            builder.append("");
            int num = 1;
            builder.append("#");
            builder.append(tabulator);
            builder.append("Initiated");
            builder.append(tabulator);
            builder.append("Finished");
            builder.append(tabulator);
            builder.append("# of Iterations");
            builder.append(tabulator);
            builder.append("Nanos");
            builder.append(tabulator);
            builder.append("Millis");
            builder.append(tabulator);
            builder.append("Secs");
            builder.append(tabulator);
            builder.append("Method");
            builder.append(tabulator);
            builder.append("Document location");
            builder.append(newLine);
            for (Result r : results) {
                builder.append(generateResultSetString(r, num));
                num++;
            }
            return builder.toString();
        }
        return EMPTY;
    }

    public static class Builder {
        private Date initiated = null;
        private long nanoResult = 0;
        private Date finished = null;
        private String documentUsed = "";
        private String callingMethod = "";
        private int numOfIterations = 0;

        public Builder() {

        }

        public Builder initiated(Date date) {
            initiated = date;
            return this;
        }

        public Builder nanoResult(long res) {
            nanoResult = res;
            return this;
        }

        public Builder finished(Date fin) {
            finished = fin;
            return this;
        }

        public Builder documentUsed(String s) {
            documentUsed = s;
            return this;
        }

        public Builder callingMethod(String s) {
            callingMethod = s;
            return this;
        }

        public Builder numOfIterations(int i) {
            numOfIterations = i;
            return this;
        }

        public Result build() {
            return new Result(this);
        }

    }

}